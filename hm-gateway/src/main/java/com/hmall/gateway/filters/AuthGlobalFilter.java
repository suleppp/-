package com.hmall.gateway.filters;

import com.hmall.common.utils.CollUtils;
import com.hmall.gateway.config.AuthProperties;
import com.hmall.gateway.util.JwtTool;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@RequiredArgsConstructor
public class AuthGlobalFilter implements GlobalFilter, Ordered {
    private final JwtTool jwtTool;
    private final AuthProperties authProperties;
    private final AntPathMatcher antPathMatcher=new AntPathMatcher();

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //获取到request
        ServerHttpRequest request = exchange.getRequest();
        //判断request当前路径是否需要拦截
        if(isExclude(request.getPath().toString())){
            //不需要拦截,直接放行
            return chain.filter(exchange);
        }

        //需要拦截
        //获取请求头上的token
        String token=null;
        List<String> headers = request.getHeaders().get("authorization");
        //解析并校验token
        if(!CollUtils.isEmpty(headers)){
            token=headers.get(0);
        }
        Long userId=null;
        try {
            userId=jwtTool.parseToken(token);
        } catch (Exception e) {
            //无效,拦截
            ServerHttpResponse response = exchange.getResponse();
            response.setRawStatusCode(401);
            return response.setComplete();
        }
        //todo 如果有效,传递用户信息
        System.out.println("userId="+userId);
        //放行
        return chain.filter(exchange);
    }


    private boolean isExclude(String antPath){
        for(String pathPattern: authProperties.getExcludePaths()){
            if (antPathMatcher.match(pathPattern,antPath)){
                return true;
            }
        }
        return false;
    }
}
