package <%=packageName%>.security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.inject.Inject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class TokenAuthenticationService {

    private static final String AUTH_HEADER_NAME = "X-JHIPSTER-AUTH";

    @Inject
    private TokenHandler tokenHandler;

    public void addAuthentication(HttpServletResponse response, UserAuthentication authentication) {
        CustomUserDetails user = (CustomUserDetails) authentication.getDetails();
        response.addHeader(AUTH_HEADER_NAME, tokenHandler.createTokenForUser(user));
    }

    public Authentication getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(AUTH_HEADER_NAME);
        if (token != null) {
            UserDetails userDetails = tokenHandler.parseUserFromToken(token);
            if (userDetails != null) {
                UserAuthentication userAuthentication = new UserAuthentication(userDetails);
                userAuthentication.setAuthenticated(true);
                return userAuthentication;
            }
        }
        return null;
    }
}
