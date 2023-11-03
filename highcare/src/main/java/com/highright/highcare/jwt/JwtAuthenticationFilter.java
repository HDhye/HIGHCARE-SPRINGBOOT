package com.highright.highcare.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.highright.highcare.auth.dto.LoginMemberDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

   private final AuthenticationManager authenticationManager;

   // Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
   // 인증 요청시에 실행되는 함수 => /login
   @Override
   public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

       log.info("JwtAuthenticationFilter : 진입");

       // request에 있는 username과 password를 파싱해서 자바 Object로 받기
       ObjectMapper objectMapper = new ObjectMapper();
       LoginMemberDTO loginRequestDto = null;
       try {
           loginRequestDto = objectMapper.readValue(request.getInputStream(), LoginMemberDTO.class);
       } catch (Exception e) {
           e.printStackTrace();
       }

       System.out.println("JwtAuthenticationFilter loginRequestDto : "+loginRequestDto);

       // 유저네임패스워드 토큰 생성
       UsernamePasswordAuthenticationToken authenticationToken =
               new UsernamePasswordAuthenticationToken(
                       loginRequestDto.getUsername(),
                       loginRequestDto.getPassword());

       System.out.println("JwtAuthenticationFilter : 토큰생성완료");



       return null;
   }
}
