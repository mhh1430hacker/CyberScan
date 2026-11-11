// CloudFront Function (viewer request), runtime cloudfront-js-2.0: "cyberscan-host-router".
// - Lambda Function URLs only accept their own Host, so CloudFront doesn't forward the visitor's;
//   this passes it on as X-Forwarded-Host (the server uses it for the Origin check and to pick the page).
// - scan.<domain>/ shows the scan app (cached separately as /app.html; the landing stays at /).
function handler(event) {
  var request = event.request;
  var host = request.headers.host ? request.headers.host.value.toLowerCase() : "";
  request.headers["x-forwarded-host"] = { value: host };
  if (host.indexOf("scan.") === 0 && (request.uri === "/" || request.uri === "/index.html")) {
    request.uri = "/app.html";
  }
  return request;
}
