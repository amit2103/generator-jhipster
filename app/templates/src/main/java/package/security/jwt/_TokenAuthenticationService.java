package <%=packageName%>.security.jwt;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.UsernamePasswordAuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Created by jhipster on 10/25/15.
 */
@Service
public class TokenAuthenticationService {

    private static final String AUTH_HEADER_NAME = "X-JHIPSTER-AUTH";
    private final TokenHandler tokenHandler;

    @Autowired
    public TokenAuthenticationService(TokenHandler tokenHandler) {
        this.tokenHandler = tokenHandler;
    }

    public void addAuthentication(HttpServletResponse response, UserAuthentication authentication) {
        //DONT NEED custom UserDetails now...removing
        final UserDetails user =  authentication.getDetails();
        response.addHeader(AUTH_HEADER_NAME, tokenHandler.createTokenForUser(user));
    }

    public Authentication getAuthentication(HttpServletRequest request) {
        final String token = request.getHeader(AUTH_HEADER_NAME);
        if (token != null) {
            final UserDetails userDetails = tokenHandler.parseUserFromToken(token);
            if (userDetails != null) {
                UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken(userDetails.getUsername(),userDetails.getPassword()
                , userDetails.getAuthorities());
                userAuthentication.setAuthenticated(true);
                return userAuthentication;
            }
        }
        return null;
    }

}