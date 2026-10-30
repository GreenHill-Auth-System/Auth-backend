
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
)

from authentication import urls as authentication_urls
from authentication.oauth_logout import GreenHillRPInitiatedLogoutView


urlpatterns = [
    # Redirect the backend homepage to the API documentation.
    path(
        "",
        RedirectView.as_view(
            url="/api/docs/",
            permanent=False,
        ),
        name="home",
    ),

    # Django administration.
    path("admin/", admin.site.urls),

    # Existing authentication endpoints.
    path("auth/", include(authentication_urls.urlpatterns)),

    # This override has to be listed *before* the ``oauth2_provider`` include
    # below: Django matches urlpatterns in order, so the included route would
    # otherwise answer ``/o/logout/`` first and this one would never be
    # reached. Everything about the standard endpoint is preserved -- it only
    # additionally retires the row in the session inventory, so signing out
    # from a relying party does not leave a phantom session listed as active.
    path(
        "o/logout/",
        GreenHillRPInitiatedLogoutView.as_view(),
        name="rp-initiated-logout",
    ),

    # OAuth 2.0 / OpenID Connect endpoints.
    path(
        "o/",
        include("oauth2_provider.urls", namespace="oauth2_provider"),
    ),

    # OpenAPI schema and interactive API documentation.
    path(
        "api/schema/",
        SpectacularAPIView.as_view(),
        name="schema",
    ),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger-ui",
    ),
]
