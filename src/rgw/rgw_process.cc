// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "common/errno.h"
#include "common/Throttle.h"
#include "common/WorkQueue.h"

#include "rgw_rados.h"
#include "rgw_rest.h"
#include "rgw_frontend.h"
#include "rgw_request.h"
#include "rgw_process.h"
#include "rgw_loadgen.h"
#include "rgw_client_io.h"

#define dout_subsys ceph_subsys_rgw

void RGWProcess::RGWWQ::_dump_queue()
{
  if (!g_conf->subsys.should_gather(ceph_subsys_rgw, 20)) {
    return;
  }
  deque<RGWRequest *>::iterator iter;
  if (process->m_req_queue.empty()) {
    dout(20) << "RGWWQ: empty" << dendl;
    return;
  }
  dout(20) << "RGWWQ:" << dendl;
  for (iter = process->m_req_queue.begin();
       iter != process->m_req_queue.end(); ++iter) {
    dout(20) << "req: " << hex << *iter << dec << dendl;
  }
} /* RGWProcess::RGWWQ::_dump_queue */


int rgw_process_authenticated(RGWHandler_REST * const handler,
                              RGWOp *& op,
                              RGWRequest * const req,
                              req_state * const s,
                              const bool skip_retarget)
{
  req->log(s, "init permissions");
  int ret = handler->init_permissions(op);
  if (ret < 0) {
    return ret;
  }

  /**
   * Only some accesses support website mode, and website mode does NOT apply
   * if you are using the REST endpoint either (ergo, no authenticated access)
   */
  if (! skip_retarget) {
    req->log(s, "recalculating target");
    ret = handler->retarget(op, &op);
    if (ret < 0) {
      return ret;
    }
    req->op = op;
  } else {
    req->log(s, "retargeting skipped because of SubOp mode");
  }

  /* If necessary extract object ACL and put them into req_state. */
  req->log(s, "reading permissions");
  ret = handler->read_permissions(op);
  if (ret < 0) {
    return ret;
  }

  req->log(s, "init op");
  ret = op->init_processing();
  if (ret < 0) {
    return ret;
  }

  req->log(s, "verifying op mask");
  ret = op->verify_op_mask();
  if (ret < 0) {
    return ret;
  }

  req->log(s, "verifying op permissions");
  ret = op->verify_permission();
  if (ret < 0) {
    if (s->system_request) {
      dout(2) << "overriding permissions due to system operation" << dendl;
    } else if (s->auth.identity->is_admin_of(s->user->user_id)) {
      dout(2) << "overriding permissions due to admin operation" << dendl;
    } else {
      return ret;
    }
  }

  req->log(s, "verifying op params");
  ret = op->verify_params();
  if (ret < 0) {
    return ret;
  }

  req->log(s, "pre-executing");
  op->pre_exec();

  req->log(s, "executing");
  op->execute();

  req->log(s, "completing");
  op->complete();

  return 0;
}

int process_request(RGWRados* const store,
                    RGWREST* const rest,
                    RGWRequest* const req,
                    const std::string& frontend_prefix,
                    const rgw_auth_registry_t& auth_registry,
                    RGWRestfulIO* const client_io,
                    OpsLogSocket* const olog)
{
  int ret = 0;

  client_io->init(g_ceph_context); // 初始化客户端，主要是从request info中取出请求头来，初始化client_io.env（RGWMongoose client_io(conn, pe->port);）

  req->log_init();  //初始化请求开始时间，及获取系统时间设置req中的时间变量ts

  dout(1) << "====== starting new request req=" << hex << req << dec
	  << " =====" << dendl;
  perfcounter->inc(l_rgw_req);  //更新性能计数器，累加请求一次。

  RGWEnv& rgw_env = client_io->get_env(); //初始化执行环境,获取client_io的env来初始化，rgw_env)

  RGWUserInfo userinfo;

  struct req_state rstate(g_ceph_context, &rgw_env, &userinfo);//存储用于完成完成请求的所有信息（Store all the state necessary to complete and respond to an HTTP request）
  struct req_state *s = &rstate;

  RGWObjectCtx rados_ctx(store, s);//初始化rados上下文
  s->obj_ctx = &rados_ctx;
  
  //初始化存储
  s->req_id = store->unique_id(req->id);
  s->trans_id = store->unique_trans_id(req->id);
  s->host_id = store->host_id;
  
  //记录日志
  req->log_format(s, "initializing for trans_id = %s", s->trans_id.c_str());

  RGWOp* op = NULL; //初始化RGWOp *op
  int init_error = 0;
  bool should_log = false;
  RGWRESTMgr *mgr; //声明RGWRESTMgr 对象

  //根据请求的url来选择对应的manager和该manager中的handler
  RGWHandler_REST *handler = rest->get_handler(store, s,
                                               auth_registry,
                                               frontend_prefix,
                                               client_io, &mgr, &init_error);
  if (init_error != 0) {
    abort_early(s, NULL, init_error, NULL);
    goto done;
  }
  dout(10) << "handler=" << typeid(*handler).name() << dendl;

  should_log = mgr->get_logging();

  req->log_format(s, "getting op %d", s->op);
  op = handler->get_op(store);
  if (!op) {
    abort_early(s, NULL, -ERR_METHOD_NOT_ALLOWED, handler);
    goto done;
  }

  req->op = op;
  dout(10) << "op=" << typeid(*op).name() << dendl;

  s->op_type = op->get_type();

  //检查请求中带的签名与本地服务端计算出的签名是否一致，判断请求是否合法详细过程见[ RGW中的请求的认证过程 ]
  req->log(s, "verifying requester");
  ret = op->verify_requester(auth_registry);
  if (ret < 0) {
    dout(10) << "failed to authorize request" << dendl;
    abort_early(s, NULL, ret, handler);
    goto done;
  }

  /* FIXME: remove this after switching all handlers to the new authentication
   * infrastructure. */
  if (nullptr == s->auth.identity) {
    s->auth.identity = rgw::auth::transform_old_authinfo(s);
  }

  req->log(s, "normalizing buckets and tenants");
  ret = handler->postauth_init(); //检查tenant和object的有效性
  if (ret < 0) {
    dout(10) << "failed to run post-auth init" << dendl;
    abort_early(s, op, ret, handler);
    goto done;
  }

  //判断用户是否被禁用
  if (s->user->suspended) {
    dout(10) << "user is suspended, uid=" << s->user->user_id << dendl;
    abort_early(s, op, -ERR_USER_SUSPENDED, handler);
    goto done;
  }

  ret = rgw_process_authenticated(handler, op, req, s);//读取并创建bucket有效性检查信息
  if (ret < 0) {
    abort_early(s, op, ret, handler);
    goto done;
  }
done:
  try {
    client_io->complete_request();
  } catch (rgw::io::Exception& e) {
    dout(0) << "ERROR: client_io->complete_request() returned "
            << e.what() << dendl;
  }

  if (should_log) {
    rgw_log_op(store, rest, s, (op ? op->name() : "unknown"), olog);
  }

  int http_ret = s->err.http_ret;
  int op_ret = 0;
  if (op) {
    op_ret = op->get_ret();
  }

  req->log_format(s, "op status=%d", op_ret);
  req->log_format(s, "http status=%d", http_ret);

  if (handler)
    handler->put_op(op);
  rest->put_handler(handler);

  dout(1) << "====== req done req=" << hex << req << dec
	  << " op status=" << op_ret
	  << " http_status=" << http_ret
	  << " ======"
	  << dendl;

  return (ret < 0 ? ret : s->err.ret);
} /* process_request */
