
from django.contrib import admin
from django.urls import include, path
from django.views.generic import RedirectView

from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
)

from authentication import urls as authentication_urls


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

    # Authentication endpoints.
    path("auth/", include(authentication_urls.urlpatterns)),

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