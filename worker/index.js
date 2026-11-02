export default {
  async fetch(request, env, ctx) {
    // 允许跨域请求（因为你的扩展需要访问它）
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    // 处理浏览器的预检请求
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // 目前只是测试，先返回一段成功的 JSON
    return new Response(JSON.stringify({ 
      success: true, 
      message: "Worker 部署成功！" 
    }), {
      headers: { 
        "Content-Type": "application/json",
        ...corsHeaders 
      },
    });
  },
};