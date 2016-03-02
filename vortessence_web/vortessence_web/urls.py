from django.conf.urls import include, url

from django.contrib import admin
admin.autodiscover()

urlpatterns = [
    url(r'^', include('web.urls')),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^ajax/', include('web.ajax_urls')),



]