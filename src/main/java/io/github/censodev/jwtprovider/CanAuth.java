package io.github.censodev.jwtprovider;

import java.util.Collection;

public interface CanAuth {
    Object subject();

    Collection<String> authorities();
}
