package site.iotify.gatewayservice.exception;

public class TokenException extends RuntimeException {
    public TokenException() {
    }

    public TokenException(String e) {
        super(e);
    }
}
