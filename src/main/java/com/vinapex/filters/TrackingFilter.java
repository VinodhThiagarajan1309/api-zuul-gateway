package com.vinapex.filters;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import com.vinapex.config.ServiceConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class TrackingFilter extends ZuulFilter {

    private static final int FILTER_ORDER = 1;
    private static final boolean SHOULD_FILTER = true;
    private static final Logger logger = LoggerFactory.getLogger(TrackingFilter.class);

    @Autowired
    ServiceConfig serviceConfig;

    @Autowired
    FilterUtils filterUtils;

    @Override
    public String filterType() {
        return FilterUtils.PRE_FILTER_TYPE;
    }

    @Override
    public int filterOrder() {
        return FILTER_ORDER;
    }

    @Override
    public boolean shouldFilter() {
        return SHOULD_FILTER;
    }

    private boolean isCorrelationIdPresent() {
        if (filterUtils.getCorrelationId() != null) {
            return true;
        }
        return false;
    }

    private String generateCorrelationId() {
        return java.util.UUID.randomUUID().toString();
    }

    @Override
    public Object run() throws ZuulException {
        if (isCorrelationIdPresent()) {
            logger.info("tmx-correlation-id found in tracking filter : {}.", filterUtils.getCorrelationId());
        } else {
            filterUtils.setCorrelationId(generateCorrelationId());
        }

        logger.info("tmx-correlation-id generated in tracking filter : {}.", filterUtils.getCorrelationId());

        RequestContext ctx = RequestContext.getCurrentContext();
        System.out.println("The organization id from the token is : " + getOrganizationId());
        filterUtils.setOrgId(getOrganizationId());
        logger.debug("Processing incoming request for {}.",  ctx.getRequest().getRequestURI());
        return null;
    }

    private String getOrganizationId() {
        String result = "";
        String authToken = "";
        if (filterUtils.getAuthToken() != null) {
            authToken = filterUtils.getAuthToken().replace("Bearer ", "");
        }

        try {
            Claims claims = Jwts.parser().setSigningKey(serviceConfig.getJwtSigningKey()
                    .getBytes("UTF-8")).parseClaimsJws(authToken).getBody();
            result = (String) claims.get("organizationId");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;
    }
}
