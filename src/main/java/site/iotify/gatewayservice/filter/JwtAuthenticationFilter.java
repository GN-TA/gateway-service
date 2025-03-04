package site.iotify.gatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
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
            try {
                ServerHttpRequest request = exchange.getRequest();

                String accessToken = null;
                if (request.getCookies().containsKey("AT")) {
                    accessToken = Objects.requireNonNull(request.getCookies().getFirst("AT")).getValue();
                }
                String refreshToken = null;
                if (request.getCookies().containsKey("RT")) {
                    refreshToken = Objects.requireNonNull(request.getCookies().getFirst("RT")).getValue();
                }
                Claims claims = getJwtClaim(secret, accessToken);
                System.out.println("이건 ?");
                boolean isExpired = claims.getExpiration().compareTo(Timestamp.valueOf(LocalDateTime.now())) <= 0;

                if (isExpired) {
                    Map<String, String> tokenMap = requestNewToken(config.getTokenServiceUrl(), accessToken, refreshToken);
                    Claims newClaims = getJwtClaim(secret, tokenMap.get("AT"));

                    ServerWebExchange serverWebExchange = exchange.mutate()
                            .request(r -> r.header("X-USER-ID", newClaims.getSubject())
                                    .header(HttpHeaders.AUTHORIZATION, tokenMap.get("AT"))
                                    .build())
                            .build();

                    serverWebExchange.getResponse().addCookie(ResponseCookie.from("RT", tokenMap.get("RT"))
                            .path("/")
                            .httpOnly(true)
                            .build());
                    return chain.filter(serverWebExchange);
                } else {
                    ServerWebExchange serverWebExchange = exchange.mutate()
                            .request(r -> r.header("X-USER-ID", claims.getSubject()).build())
                            .build();
                    return chain.filter(serverWebExchange);
                }
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                e.printStackTrace();
                throw new TokenException();
            }
        });
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

    private Claims getJwtClaim(String secret, String token) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PublicKey publicKey = getPublicKey(secret);
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private PublicKey getPublicKey(String secretKey) throws InvalidKeySpecException, NoSuchAlgorithmException {
        System.out.println(">>> ENV PUBLIC_KEY : "+secretKey);
        String s = secretKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        System.out.println(">>> s = " + s);

        byte[] decodedKey = Base64.getDecoder().decode(s);
        System.out.println(">>> decodedKey = " + s);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // RSA 또는 EC
        return keyFactory.generatePublic(keySpec);
    }
}
