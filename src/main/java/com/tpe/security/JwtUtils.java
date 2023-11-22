package com.tpe.security;

import org.springframework.stereotype.Component;

import com.tpe.security.service.UserDetailsImpl;
import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;


import java.util.Date;

@Component
public class JwtUtils {

    private String jwtSecret = "sboot";
    private long jwtExpirationMs = 86400000;  //24*60*60*1000 ( 1 gun)

    // Not: GENERATE JWT TOKEN ******************
    public String generateToken(Authentication authentication){

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder().
                setSubject(userDetails.getUsername()).
                setIssuedAt(new Date()).
                setExpiration(new Date(new Date().getTime()+ jwtExpirationMs)).
                signWith(SignatureAlgorithm.HS512, jwtSecret).
                compact();
    }


    // Not: VALIDATE JWT TOKEN *******************
    public boolean validateToken(String token){
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            e.printStackTrace();
        } catch (UnsupportedJwtException e) {
            e.printStackTrace();
        } catch (MalformedJwtException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        }

        return false;
    }

    // Not: JWT TOKENDEN USERNAME  BILGISINI CEKECEGIZ *****
    public String getUserNameFromJwtToken(String token){

        return Jwts.parser().
                setSigningKey(jwtSecret).
                parseClaimsJws(token).
                getBody().getSubject();
    }
}
