
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
)

from authentication import urls as authentication_urls
from authentication.views import oidc_sign_out


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

    # ISMP returns here after signing out; always send users to the auth login.
    path(
        "o/logout/",
        oidc_sign_out,
        name="oidc_sign_out",
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
