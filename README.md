# HIGHCARE-SPRINGBOOT
하이케어 프로젝트_백엔드
<br>
목적: 스프링부트 기반의 REST API 서버를 연동한 그룹웨어 및 React.js SPA 애플리케이션 개발과 Docker를 활용한 AWS 클라우드 배포 

## 🖥️ 프로젝트 소개
효율적인 의사소통 및 효과적인 정보공유를 가능하게 하는 중앙 집중식 그룹웨어 플랫폼입니다.
<br>

## 🕰️ 개발 기간
23.07.25 - 23.09.14
<br>

### 🧑‍🤝‍🧑 맴버 구성 
- **팀원1: 황다혜 - 시큐리티,JWT인증방식 일반/소셜 로그인, 계정찾기, 비밀번호 변경, 관리자페이지 회원관리, 권한관리, 접속로그, 로깅, 에러핸들러, 예외처리, AWS 클라우드 배포**
- 팀원2: 김나경 - 전자결재 
- 팀원3: 전아림 - 인사관리, 조직도 
- 팀원4: 조혜란 - 마이페이지
- 팀원5: 허유일 - 시설예약, 게시판
- 팀원6: 홍다희 - 채팅
- 공통: 서비스 기획 및 ERD 설계, REST API 개발 

### ⚙️ 개발 환경
- Java 11
- Framework : Springboot(2.x)
- Database : Oracle DB(11xe), Redis DB(7.x)
- ORM : JPA

## 📌 주요 기능 <a href="https://github.com/HDhye/HIGHCARE-SPRINGBOOT/wiki/%ED%95%98%EC%9D%B4%EC%BC%80%EC%96%B4(%EB%B0%B1%EC%97%94%EB%93%9C)"> - 상세 보기(wiki 이동)
#### [시큐리티/로그인(JWT인증방식)](https://github.com/HDhye/HIGHCARE-SPRINGBOOT/tree/main/highcare/src/main/java/com/highright/highcare/auth)
- 일반 로그인 
- [소셜 로그인: OAuth2 인증방식 API 연동(구글, 카카오)](https://github.com/HDhye/HIGHCARE-SPRINGBOOT/tree/main/highcare/src/main/java/com/highright/highcare/oauth)
- 계정찾기
- 비밀번호 변경 구현
#### [관리자 페이지](https://github.com/HDhye/HIGHCARE-SPRINGBOOT/tree/main/highcare/src/main/java/com/highright/highcare/admin)
- 회원관리
- 권한관리
- 접속로그
#### 비즈니스로직 공통 관심사
- 로깅
- 에러핸들러


