package com.highright.highcare.jwt;

import com.highright.highcare.auth.dto.AccountDTO;
import com.highright.highcare.auth.dto.LoginMemberDTO;
import com.highright.highcare.auth.dto.TokenDTO;
import com.highright.highcare.auth.entity.AUTHRefreshToken;
import com.highright.highcare.common.AdminCustomBean;
import com.highright.highcare.exception.TokenException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.IOException;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider {

    private final String BEARER_TYPE = "Bearer"; // 토큰 타입
    private final String AUTHORITIES_KEY = "auth";   // 권한클레임 key값
    private final Key key;     // access 토큰 전용 시크릿키

   @Value("${jwt.expire-time}")
    public static long ACCESS_TOKEN_EXPIRE_TIME; 
   @Value("${jwt.refresh-expire-time}")
    public static long REFRESH_TOKEN_EXPIRE_TIME;    


    private final UserDetailsService userDetailsService;
    private final AdminCustomBean adminCustomBean;
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String REFRESHKEY_HEADER = "RefreshToken";

    public TokenProvider(@Value("${jwt.secret}") String secretAccessKey, UserDetailsService userDetailsService, AdminCustomBean adminCustomBean) {
        this.userDetailsService = userDetailsService;
        this.adminCustomBean = adminCustomBean;
        byte[] AkeyBytes = Decoders.BASE64.decode(secretAccessKey);
        this.key = Keys.hmacShaKeyFor(AkeyBytes);

    }

    // 1. 토큰 생성
    public TokenDTO generateTokenDTO(LoginMemberDTO loginMemberDTO) {
        log.info("[TokenProvider] generateTokenDTO : loginMemberDTO === {}", loginMemberDTO);


        // 클레임 설정(회원아이디, 권한)
        Claims claims = Jwts.claims().setSubject(loginMemberDTO.getUsername()); // id
        claims.put(AUTHORITIES_KEY, loginMemberDTO.getRoleList().stream()
                                    .map(role -> role.getAuthCode()).distinct()
                                    .collect(Collectors.toList())); // "auth" - "roles"

        // 만료시간 설정
        long now = System.currentTimeMillis();
        Date AccessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);

        String accessToken = Jwts.builder()
                .setClaims(claims)
                .setExpiration(AccessTokenExpiresIn)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();

        log.info("[TokenProvider] generateTokenDTO : accessToken === {}", accessToken);

        return TokenDTO.builder().grantType(BEARER_TYPE)
                .accessToken(accessToken)
                .accessTokenExpiresIn(now + ACCESS_TOKEN_EXPIRE_TIME)
                .refreshTokenExpiresIn(now + REFRESH_TOKEN_EXPIRE_TIME)
                .memberName(loginMemberDTO.getName())
                .empNo(loginMemberDTO.getEmpNo())
                .deptName(loginMemberDTO.getDeptName())
                .jobName(loginMemberDTO.getJobName())
                .role(loginMemberDTO.getRoleList().toString())
                .isTempPwd(loginMemberDTO.getIsTempPwd())
                .accountDTO(AccountDTO.builder().isTempPwd(loginMemberDTO.getIsTempPwd()).pwdExpiredDate(loginMemberDTO.getPwdExpiredDate()).build())
                .build();
    }

    /**
     * TokenProvider 헤더에서 토큰정보 추출(bearer 뒷부분)
     * @author hdhye
     * 작성일 2023-08-19
     **/
    public String resolveToken(HttpServletRequest request) {


        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        log.info("[TokenProvider] resolveToken : bearetToken === {}",bearerToken);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_TYPE)) {
            // 전송받은 값에서 'Bearer ' 뒷부분(jwt token - 1번 인덱스) 추출
            return bearerToken.split(" ")[1];
        }

        return null;
    }

    /**
     * TokenProvider 토큰 유효성 검사
     *
     * @author hdhye
     * 작성일 2023-08-19
     **/
    public boolean validateToken(String jwt) throws ServletException, IOException {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt);
            return true; // 위 코드 정상동작(유효)되면 true 반환됨, 예외발생시 안되면 catch 실행
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            throw new TokenException("잘못된 JWT 서명이나 형식으로 검증에 실패하였습니다.");
        } catch (ExpiredJwtException e) {
            return false;
//            throw new TokenException("만료된 JWT 서명입니다.");
        } catch (UnsupportedJwtException e) {
            throw new TokenException("지원되지 않는 JWT 서명입니다.");
        } catch (IllegalArgumentException e) {
            throw new TokenException("JWT 토큰이 잘못되었습니다.");
        }
    }

    /**
     * TokenProvider 토큰 클레임 추출 메소드
     * @author hdhye
     * 작성일 2023-08-19
     **/
    public Claims parseClaims(String jwt) {
        try {
            // jwts 파서빌더 -> 사인키값 셋팅 -> 빌드 -> 클레임 파싱 -> 바디내용 취득
            return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt).getBody();
            // 만료시 예외처리 --- 프론트에서 만료를 잡지 못하고 넘긴 경우 처리해야함

        } catch (ExpiredJwtException e) {
            return e.getClaims();   // 토큰이 만료되어 예외가 발생하더라도 클레임 값을 뽑는다.
        }
        // 리프레쉬 토큰이 만료되지 않았으면 엑세스 토큰만 재생성되는 메소드
    }

    /**
     * TokenProvider token 인증 객체 추출하여 권한 넘기기
     * @author hdhye
     * 작성일 2023-08-19
     **/
    public Authentication getAuthentication(String jwt) {

        // 클레임 추출(복호화)
        Claims claims = parseClaims(jwt);

        if(claims.get(AUTHORITIES_KEY) == null){
            throw new TokenException("권한 정보가 없는 토큰입니다.");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(claims.getSubject());
        log.info("[TokenProvider] getAuthentication : getAuthorities === {}", userDetails.getAuthorities());

        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
    *TokenProvider refresh토큰 쿠키 생성기
    *@author hdhye
    *작성일 2023-08-21
    **/
    public Cookie generateRefreshTokenInCookie(LoginMemberDTO loginMemberDTO){

        // 리프레쉬 토큰 생성 ( "uuid + id")
        String refreshToken = adminCustomBean.randomRefreshToken() + loginMemberDTO.getId();
        // 쿠키에 헤더와 담는다
        String cookieName = REFRESHKEY_HEADER;
        String cookieValue = refreshToken;
        log.info("[TokenProvider] generateRefreshTokenInCookie : refreshToken === {}", refreshToken);

        Cookie cookie = new Cookie(cookieName, cookieValue);
        cookie.setHttpOnly(true);             // httponly 옵션 설정
        cookie.setSecure(false);               // https 옵션 설정
        cookie.setPath("/");            // 모든 곳에서 쿠키열람 가능
        cookie.setMaxAge((int) REFRESH_TOKEN_EXPIRE_TIME);         // 쿠키 만료시간 설정

        return cookie;
    }

    /**
     *TokenProvider refresh토큰 쿠키 리졸버
     *@author hdhye
     *작성일 2023-08-21
     **/
    // 헤더 쿠키에 있는refresh토큰 resolver
    public AUTHRefreshToken resolveCookie(HttpServletRequest request) {

        log.info("[TokenProvider] resolveCookie : request === {}",request);

        Cookie[] cookies = request.getCookies();

        String refreshToken = "";
        String memberId = "";

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (REFRESHKEY_HEADER.equals(cookie.getName())) {
                    String[] cookieValues = cookie.getValue().split("=");
                    if (cookieValues.length >= 2) {
                        refreshToken = cookieValues[0];
                        memberId = cookieValues[1];
                        break; // 원하는 쿠키를 찾으면 루프 종료
                    }
                }
            }
        }
        //f04b112a-1c52-4ecf-9a18-b9385192403b=user01
        log.info("[TokenProvider] resolveCookie : refreshToken === {}",refreshToken);
        log.info("[TokenProvider] resolveCookie : memberId === {}",memberId);
        return AUTHRefreshToken.builder()
                .refreshToken(refreshToken)
                .id(memberId)
                .build();
    }

    // access 토큰 아이디
    public String getUserId(String jwt) {
        log.info("[TokenProvider] getUserId : jwt === {}",jwt);

              return Jwts.parserBuilder()
                .setSigningKey(key).build()
                .parseClaimsJws(jwt)
                .getBody()
                .getId(); // claims 추출
                // subject에 id, auth값 담겨있음
    }


    public String createOauthToken(String email, String role) {

        Claims claims = Jwts.claims().setSubject(email);
        claims.put("role", role);
        Date now = new Date();
        Date validity = new Date(now.getTime() + ACCESS_TOKEN_EXPIRE_TIME);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();
    }
}
