package org.chuanshen.filter;

import org.chuanshen.model.IpAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class IpAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
    // 使用 /ipVerify 该端点进行 ip 认证
    public IpAuthenticationProcessingFilter(AuthenticationManager authenticationManager) {
        super(new AntPathRequestMatcher("/ipVerify"));
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        // 获取 host 信息
        String host = request.getRemoteHost();
        // 交给内部的 AuthenticationManager 去认证, 实现解耦
        return getAuthenticationManager().authenticate(new IpAuthenticationToken(host));
    }
}
