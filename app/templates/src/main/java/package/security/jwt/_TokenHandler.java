package <%=packageName%>.security.jwt;

import com.google.common.base.Preconditions;
import com.technicalrex.springsecurityjwt.support.validation.StringConditions;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;

public final class TokenHandler {

    private final String secret;
    private final UserService userService;
    private final int tokenValidity;

    public TokenHandler(String secret, UserService userService) {
        this.secret = StringConditions.checkNotBlank(secret);
        this.userService = Preconditions.checkNotNull(userService);
    }

    public UserDetails parseUserFromToken(String token) {
        String decryptedtoken = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        String tokens = decryptedtoken.split(":);
        String username = tokens[0];
        return userService.loadUserByUsername(username);
    }

    public String computeSignature(UserDetails userDetails, long expires) {
        StringBuilder signatureBuilder = new StringBuilder();
        signatureBuilder.append(userDetails.getUsername()).append(":");
        signatureBuilder.append(expires).append(":");
        signatureBuilder.append(userDetails.getPassword()).append(":");
        signatureBuilder.append(secretKey);
        return signatureBuilder.toString();
     }

    public String createTokenForUser(UserDetails user) {
        long expires = long expires = System.currentTimeMillis() + 1000L * tokenValidity;
        return Jwts.builder()
                .setSubject(user.getUsername() + ":" + computeSignature(user,expires))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }
}
