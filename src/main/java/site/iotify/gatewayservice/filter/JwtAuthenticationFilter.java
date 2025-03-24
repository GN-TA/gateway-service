package site.iotify.gatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.server.Cookie;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import site.iotify.gatewayservice.exception.TokenException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

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

    @Override
    public GatewayFilter apply(Config config) {
        String secret = config.getSecretKey();
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            String accessToken = extractTokenFromCookie(request, response, "AT");
            if (accessToken == null) return response.setComplete();
            String refreshToken = extractTokenFromCookie(request, response, "RT");
            if (refreshToken == null) return response.setComplete();

            try {
                PublicKey publicKey = getPublicKey(secret);

                Claims claims = validateAndProcessToken(
                        publicKey,
                        accessToken,
                        refreshToken,
                        config.getTokenServiceUrl(),
                        exchange
                );

                ServerWebExchange serverWebExchange = exchange.mutate()
                        .request(r -> r.header("X-USER-ID", claims.getSubject()).build())
                        .build();

                return chain.filter(serverWebExchange);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                log.error("Key parsing error: {}", e.getMessage());
                throw new TokenException();
            } catch (Exception e) {
                log.error("Unexpected error: {}", e.getMessage());
                response.setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }
        });
    }

    private Claims validateAndProcessToken(PublicKey publicKey,
                                           String accessToken,
                                           String refreshToken,
                                           String tokenServiceUrl,
                                           ServerWebExchange exchange) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();

        } catch (ExpiredJwtException e) {
            Map<String, String> tokenMap = requestNewToken(tokenServiceUrl, accessToken, refreshToken);

            if (tokenMap == null || !tokenMap.containsKey("AT") || !tokenMap.containsKey("RT")) {
                log.error("Failed to refresh token");
                throw new TokenException();
            }
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(tokenMap.get("AT"))
                    .getBody();

            exchange.getResponse().addCookie(ResponseCookie.from("AT", tokenMap.get("AT"))
                    .path("/")
                    .httpOnly(true)
                    .secure(true)
                    .build());
            exchange.getResponse().addCookie(ResponseCookie.from("RT", tokenMap.get("RT"))
                    .path("/")
                    .httpOnly(true)
                    .secure(true)
                    .build());
            return claims;
        }
    }

    private String extractTokenFromCookie(ServerHttpRequest request, ServerHttpResponse response, String tokenName) {
        if (!request.getCookies().containsKey(tokenName)) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return null;
        }
        return request.getCookies().getFirst(tokenName).getValue();
    }

    private Map<String, String> requestNewToken(String tokenServiceUrl, String token, String refreshToken) {
        WebClient webClient = WebClient.builder().build();

        Map<String, String> response = webClient.post()
                .uri(tokenServiceUrl + "/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "bearer " + token)
                .cookie("RT", refreshToken)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {
                })
                .block();

        if (response == null || !response.containsKey("newToken")) {
            throw new TokenException();
        }

        return response;
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
