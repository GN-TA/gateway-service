package site.iotify.gatewayservice.hadler;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import site.iotify.gatewayservice.dto.ErrorResponse;
import site.iotify.gatewayservice.exception.TokenException;

import java.security.SignatureException;

@Slf4j
@Component
@RequiredArgsConstructor
public class ExceptionHandler implements ErrorWebExceptionHandler {
    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        if (ex instanceof SignatureException ||
                ex instanceof JwtException ||
                ex instanceof TokenException) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
        } else {
            response.setStatusCode(HttpStatus.NOT_FOUND);
        }
//        log.error(ex.getMessage());
        ex.printStackTrace();

        return response.writeWith(
                Mono.just(response
                        .bufferFactory()
                        .wrap(serializeMessage(ex.getMessage()))
                )
        );
    }

    private byte[] serializeMessage(String message) {
        ErrorResponse errorResponse = new ErrorResponse(message);
        try {
            return objectMapper.writeValueAsBytes(errorResponse);
        } catch (JsonProcessingException e) {
            return "Error".getBytes();
        }
    }
}
