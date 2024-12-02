package site.iotify.gatewayservice.fiter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;
import site.iotify.gatewayservice.exception.TokenException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    @Setter
    public static class Config {
        private String secretKey;
    }

    @Override
    public GatewayFilter apply(Config config) {
        String secret = config.getSecretKey();

        return ((exchange, chain) -> {
            try {
                List<String> auths = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
                if (auths == null) {
                    throw new TokenException();
                }
                Claims claims = getJwtClaim(secret, auths.get(0));

                ServerWebExchange serverWebExchange = exchange.mutate()
                        .request(r -> r.header("X-USER-ID", claims.getSubject()).build())
                        .build();

                return chain.filter(serverWebExchange);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                throw new TokenException();
            }
        });
    }

    private Claims getJwtClaim(String secret, String token) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PublicKey publicKey = getPublicKey(secret);

        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
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
