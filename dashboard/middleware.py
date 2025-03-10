import logging

logger = logging.getLogger('dashboard')

class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        logger.debug("Incoming request - method: %s, path: %s, body: %s", 
                     request.method, request.path, request.body.decode('utf-8') if request.body else "No body")
        logger.debug("Request headers: %s", dict(request.headers))

        response = self.get_response(request)

        logger.debug("Response status: %d, content: %s", 
                     response.status_code, response.content.decode('utf-8') if response.content else "No content")
        return response