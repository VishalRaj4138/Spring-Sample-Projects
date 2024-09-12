package com.example.Securitydemo.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

//This is our Jwt Helper class where we are creating and receiving the token and getting the user details from the token
//as well as the most important thing validating the token as checking whether the token is correct or not or expired or active.
@Component
public class JwtUtils {
    public static final org.slf4j.Logger logger =  LoggerFactory.getLogger(JwtUtils.class);

    //This is jwt token Secret key use to encode and decode the token
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    //This is jwt token expiration time fetching from application.properties
    @Value(("${spring.app.jwtExpirationMs}"))
    private int jwtExpirationMs;

    //Retrieving the jwt token from header and removing the bearer keyword
    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}",bearerToken);
        if(bearerToken != null && bearerToken.startsWith("Bearer "))
            return bearerToken.substring(7);
        return null;
    }

    //creation of Jwt token using the user details sch as here we are using the username only to create the token
    public String generateTokenFromUsername(UserDetails userDetails){
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    public String getUserNameFromJwtToken(String token){
        return Jwts.parser().verifyWith((SecretKey) key()).
                build().parseSignedClaims(token).
                getPayload().getSubject();
    }

    //decoding the token with help of secret key
    public Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    //checking the validity of token
    public boolean validateJwtToken(String authToken) {
        try{
            System.out.println("Validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;
        }catch (MalformedJwtException e){
            logger.error("Invalid JWT Token: {}",e.getMessage());
        }catch (ExpiredJwtException e){
            logger.error("JWT Token is expired: {}",e.getMessage());
        }catch (UnsupportedJwtException e){
            logger.error("JWT Token is unsupported: {}",e.getMessage());
        }catch (IllegalArgumentException e){
            logger.error("JWT claims string is empty: {}",e.getMessage());
        }
        return false;
    }

}
