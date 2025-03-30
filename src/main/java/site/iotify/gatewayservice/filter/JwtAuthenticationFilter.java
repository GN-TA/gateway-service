package site.iotify.gatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import site.iotify.gatewayservice.exception.TokenException;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

@Slf4j
@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    @Setter
    public static class Config {
        private String secretKey;
        private String tokenServiceUrl;
    }

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    /**
     * 1. 유효한 액세스 토큰, 유효한 리프레시 토큰 (200) => good,
     * 2. 만료된 액세스 토큰, 유효한 리프레시 토큰 (토큰 서비스는 레디스에 저장된 리프레시 토큰 확인후 유효시 200) => good,
     * 3. 만료된 액세스 토큰, 만료된 리프레시 토큰 (토큰 서비스는 리프레시 토큰 만료시 401 쿠키지움) => good
     * 4. 만료된 액세스 토큰, 블랙리스트 리프레시 토큰 (401 && )
     *
     * @param config
     * @return
     */
    @Override
    public GatewayFilter apply(Config config) {
        String secret = config.getSecretKey();
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            String accessToken = extractTokenFromCookie(request, response, "AT");
            String refreshToken = extractTokenFromCookie(request, response, "RT");
            if (accessToken == null || refreshToken == null) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }
            return Mono.fromCallable(() -> getPublicKey(secret))
                    .flatMap(publicKey -> validateAndProcessToken(publicKey, accessToken, refreshToken, config.tokenServiceUrl, exchange))
                    .flatMap(claims -> {
                        ServerWebExchange serverWebExchange = exchange.mutate()
                                .request(r -> r.header("X-USER-ID", claims))
                                .build();
                        return chain.filter(serverWebExchange);
                    })
                    .onErrorResume(TokenException.class, e -> {
                        log.error("asdf" + response.getHeaders().get(HttpHeaders.SET_COOKIE));
                        return response.setComplete();
                    });
        });
    }

    // 검증이 필요한 요청들 검증 로직
    private Mono<String> validateAndProcessToken(PublicKey publicKey,
                                                 String accessToken,
                                                 String refreshToken,
                                                 String tokenServiceUrl,
                                                 ServerWebExchange exchange) {
        try {
            // 액세스토큰 검증
            return Mono.just(
                    Jwts.parserBuilder()
                            .setSigningKey(publicKey)
                            .build()
                            .parseClaimsJws(accessToken)
                            .getBody().getSubject()
            );
            //액세스 토큰 만료시
        } catch (ExpiredJwtException e) {
            return requestNewToken(exchange, tokenServiceUrl, accessToken, refreshToken)
                    .flatMap(tokenMap -> {
                        Claims claims = Jwts.parserBuilder()
                                .setSigningKey(publicKey)
                                .build()
                                .parseClaimsJws(tokenMap.get("accessToken"))
                                .getBody();
                        exchange.getResponse().addCookie(
                                ResponseCookie.from("AT", tokenMap.get("accessToken"))
                                        .path("/")
                                        .secure(true)
                                        .build()
                        );
                        exchange.getResponse().addCookie(
                                ResponseCookie.from("RT", tokenMap.get("refreshToken"))
                                        .path("/")
                                        .httpOnly(true)
                                        .secure(true)
                                        .build()
                        );
                        return Mono.just(claims.getSubject());
                    })
                    .onErrorMap(throwable -> {
                        log.error(throwable.getMessage());
                        log.error(exchange.getRequest().getPath() + " Token refresh failed");
                        return new TokenException();
                    });
        }
    }

    private String extractTokenFromCookie(ServerHttpRequest request, ServerHttpResponse response, String tokenName) {
        if (!request.getCookies().containsKey(tokenName)) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return null;
        }
        return Objects.requireNonNull(request.getCookies().getFirst(tokenName)).getValue();
    }

    private Mono<Map<String, String>> requestNewToken(ServerWebExchange exchange,
                                                      String tokenServiceUrl,
                                                      String token,
                                                      String refreshToken) {
        WebClient webClient = WebClient.builder().build();
        return webClient.post()
                .uri(tokenServiceUrl + "/v1/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .cookie("AT", token)
                .cookie("RT", refreshToken)
                .exchangeToMono(clientResponse -> {
                    HttpStatus status = (HttpStatus) clientResponse.statusCode();
                    HttpHeaders headers = clientResponse.headers().asHttpHeaders();

                    log.error("Token service response status: {}", status);
                    log.error("Token service response headers: {}", headers);
                    List<String> setCookieHeaders = headers.get(HttpHeaders.SET_COOKIE);
                    // 리프레시 토큰 유효시
                    if (status.is2xxSuccessful()) {
                        return clientResponse.bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {
                                })
                                .flatMap(responseBody -> {
                                    if (responseBody == null || !responseBody.containsKey("accessToken") ||
                                            !responseBody.containsKey("refreshToken")) {
                                        return Mono.error(new TokenException());
                                    }
                                    return Mono.just(responseBody);
                                });
                        // 리프레시 토큰 만료시
                    } else {
                        // 토큰 서비스에서 받은 Set-Cookie 헤더를 Gateway 응답에 추가
                        if (setCookieHeaders != null) {
                            setCookieHeaders.forEach(cookie ->
                                    exchange.getResponse().getHeaders().add(HttpHeaders.SET_COOKIE, cookie)
                            );
                        }
                        return Mono.error(new TokenException());
                    }
                });
    }

    private PublicKey getPublicKey(String secretKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String s = secretKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decodedKey = Base64.getDecoder().decode(s);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // RSA 또는 EC
        return keyFactory.generatePublic(keySpec);
    }
}
