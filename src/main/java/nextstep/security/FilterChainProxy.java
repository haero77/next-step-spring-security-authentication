package nextstep.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class FilterChainProxy implements Filter {

    public static final String FILTER_CHAIN_PROXY_BEAN_NAME = "springSecurityFilterChain";

    private final List<SecurityFilterChain> securityFilterChains;

    public FilterChainProxy(List<SecurityFilterChain> securityFilterChains) {
        this.securityFilterChains = securityFilterChains;
    }

    @Override
    public void doFilter(
            ServletRequest servletRequest,
            ServletResponse servletResponse,
            FilterChain originalChain
    ) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;

        Optional<SecurityFilterChain> securityFilterChainOpt = findSecurityFilterChainToExecute(httpRequest);

        if (securityFilterChainOpt.isEmpty()) {
            originalChain.doFilter(servletRequest, servletResponse);
            return;
        }

        // SecurityFilterChain을 먼저 실행하고, 그 다음에 원래의 FilterChain을 실행한다.
        SecurityFilterChain securityFilterChain = securityFilterChainOpt.get();
        FilterChain withSecurityFilterChainAdded = new VirtualFilterChain(originalChain, securityFilterChain.getFilters());
        withSecurityFilterChainAdded.doFilter(servletRequest, servletResponse);
    }

    private Optional<SecurityFilterChain> findSecurityFilterChainToExecute(HttpServletRequest request) {
        if (Objects.isNull(this.securityFilterChains) || this.securityFilterChains.isEmpty()) {
            return Optional.empty();
        }

        return this.securityFilterChains.stream()
                .filter(securityFilterChain -> securityFilterChain.matches(request))
                .findFirst();
    }

    private static final class VirtualFilterChain implements FilterChain {

        private final FilterChain originalChain;
        private final List<Filter> additionalFilters;
        private final int additionalFiltersSize;
        private int currentPosition = 0;

        public VirtualFilterChain(FilterChain originalChain, List<Filter> additionalFilters) {
            this.originalChain = originalChain;
            this.additionalFilters = additionalFilters;
            this.additionalFiltersSize = additionalFilters.size();
        }

        @Override
        public void doFilter(
                ServletRequest servletRequest,
                ServletResponse servletResponse
        ) throws IOException, ServletException {
            if (allAdditionalFiltersExecuted()) {
                executeOriginalFilterChain(servletRequest, servletResponse);
                return;
            }

            // 실행해야 할 additionalFilter 가 남아있는 경우
            executeNextFilterInAdditionalFilters(servletRequest, servletResponse);
        }

        private void executeNextFilterInAdditionalFilters(
                ServletRequest servletRequest,
                ServletResponse servletResponse
        ) throws IOException, ServletException {
            this.currentPosition++;
            Filter nextFilter = additionalFilters.get(currentPosition - 1);
            nextFilter.doFilter(servletRequest, servletResponse, this);
        }

        private boolean allAdditionalFiltersExecuted() {
            return this.currentPosition == this.additionalFiltersSize;
        }

        private void executeOriginalFilterChain(
                ServletRequest servletRequest,
                ServletResponse servletResponse
        ) throws IOException, ServletException {
            originalChain.doFilter(servletRequest, servletResponse);
        }
    }
}
