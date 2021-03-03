# Spring-Boot JWT

A Spring Boot application using JWT security.

## Getting Started

Just clone this repository and open it using Eclipse.

### Prerequisites

This project currently requires Java 11 and it's using Spring Boot 2.4.3.

### Running the application

Just start it like any other Spring Boot application. The main method from SpringJwtApplication is the entrypoint.

Each time you start the server an user is created for you. You can login into the application using the following credentials:
```
{
    "username": "pacaccini.tavares",
    "password": "ubirajara"
}
```
Upon a successful login, you can try out the secure endpoint.

You can change some JWT settings on the [application.yaml](https://github.com/felipeAndrade0918/spring-boot-jwt/blob/master/src/main/resources/application.yaml) file.

You can access the swagger-ui through the following address: http://localhost:8080/swagger-ui/index.html

### How is JWT implemented in here?

The main configuration resides in the [SecurityConfig](https://github.com/felipeAndrade0918/spring-boot-jwt/blob/master/src/main/java/com/felipeandrade0918/springjwt/config/security/SecurityConfig.java) class.

Since we are using JWT, there's no need for session state. We can set the session as stateless with [this line](https://github.com/felipeAndrade0918/spring-boot-jwt/blob/master/src/main/java/com/felipeandrade0918/springjwt/config/security/SecurityConfig.java#L53):
```
sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
```

These two filters ([AuthenticationFilter](https://github.com/felipeAndrade0918/spring-boot-jwt/blob/master/src/main/java/com/felipeandrade0918/springjwt/config/security/filter/AuthenticationFilter.java) and [AuthorizationFilter](https://github.com/felipeAndrade0918/spring-boot-jwt/blob/master/src/main/java/com/felipeandrade0918/springjwt/config/security/filter/AuthorizationFilter.java)) do the heavy work.
```
.addFilter(new AuthenticationFilter(authenticationManager(), jwtService))
.addFilter(new AuthorizationFilter(authenticationManager(), jwtService))
```

The AuthenticationFilter is responsible for authenticating the user. After a successful authentication, the JWT is created and written in the response.

The AuthorizationFilter is responsible for retrieving and validating the token on each request.

The principal object can be accessed through the @AuthenticationPrincipal annotation:
```
public String securityTest(@AuthenticationPrincipal Long userId) {
```
