## Varnish para sitios de conferencias 
# Usa a Drupal. Casos especiales o redirecci{on del subdominio wwww se envia a SADE
# Mas que nada, aparte del cache, controla el acceso a la administracion de los sitios Drupal
##################
#  ver 2.25
#  -> Control de acceso a la administracion sitio observatoriop10
#
##################

# allowing access from the public internet.
# acl internal {
#  "192.10.0.0"/24;
# }

import std; 
include "/etc/varnish/deny_admin.vcl";

acl purge {
        "10.0.17.207";
		"10.0.17.127";  ## Andrea Carrillo
		"10.0.0.0"/16; ## cepal santiago completa
		# para poder hacer purge desde back-end (Administracion de contenidos en Drupal)
		 "localhost";
		 "127.0.0.1";
}


# Default backend definition.  Set this to point to your content
# server.
#

probe drupal_healthcheck {
  .url = "/";
  .timeout = 100ms;
  .interval = 2s;
  .window = 5;
  .threshold = 2;
}

backend drupal {
  .host = "10.0.9.63";
  .port = "80";
  .probe=drupal_healthcheck;

#  .connect_timeout = 600s;
#  .first_byte_timeout = 600s;
#  .between_bytes_timeout = 600s;
}

#SADE
backend sade 
{
   #.host = "200.9.3.94";
   .host = "10.0.40.52";
   .port = "80";
}


sub centraliza_dominios{
	## 
	# CU-01: Reescribir dominio. www.cepal.cl, www.eclac.cl y www.eclac.org se redireccionan a www.cepal.org
	## CU-01:------------- Desde acá 
    if (req.http.host ~ "^(www\.)cepal\.cl" || 
        req.http.host ~ "^(www\.)eclac\.cl"  || 
        req.http.host ~ "^(www\.)eclac\.org" ) 
    {
        error 750 "http://www.cepal.org" + req.url;
    } 
	## 
	# CU-01.1 : Reescribir dominio. *.eclac.org se redireccionan a *.cepal.org
	# 26-feb-2015
	## 
    if (req.http.host ~ "eclac\.org" ) 
    {
		error 751  "http://" + regsub(req.http.host,"eclac\.org", "cepal\.org") + req.url;
    } 
    if (req.http.host ~ "eclac\.cl" ) 
    {
		error 751  "http://" + regsub(req.http.host,"eclac\.cl", "cepal\.org") + req.url;
    } 
	if (req.http.host ~ "cepal\.cl" ) 
    {
		error 751  "http://" + regsub(req.http.host,"cepal\.cl", "cepal\.org") + req.url;
    } 
	# FIN CU-01.1 
	# ----------------------
	
	## 
	# CU-02: Redirigir a SADE dominios existentes, con código 302:
	# socinfo.cepal.org
	# www.ilpes.cl
	# www.ofilac.org
	# www.eclacpos.org
	# www.cepal.org.mx
	## CU-02:------------- Desde acá 
	if (req.http.host ~ "^socinfo.cepal.org") 
    {
        #error 751 "http://www.cepal.org/socinfo/" + req.url;
		error 751 "http://www.cepal.org/socinfo" + req.url;
    } 
	if (req.http.host ~ "^www.ilpes.cl") 
    {
        #error 751 "http://www.cepal.org/ilpes/" + req.url;
		error 751 "http://www.cepal.org/ilpes" + req.url;
    } 
	if (req.http.host ~ "^www.ofilac.org") 
    {
        #error 751 "http://www.cepal.org/ofilac/" + req.url;
		error 751 "http://www.cepal.org/ofilac" + req.url;
    }
	if (req.http.host ~ "^www.eclacpos.org") 
    {
        #error 751 "http://www.cepal.org/portofspain/" + req.url;
		error 751 "http://www.cepal.org/portofspain" + req.url;
    }
	if (req.http.host ~ "^www.cepal.org.mx") 
    {
		# Modificado el 9 de Junio 2015 - JPI
        # el dominio www.cepal.org.mx no llega con parámetros, por lo que el destino no debe terminar con /
		#error 751 "http://www.cepal.org/mexico/" + req.url;
		error 751 "http://www.cepal.org/mexico";
    }
	## CU-02 - HASTA ACÁ
}

# Respond to incoming requests.
sub vcl_recv {
## 
	# CU-01: Reescribir dominio. www.cepal.cl, www.eclac.cl y www.eclac.org se redireccionan a www.cepal.org
	## 
	# CU-01 y 02: Redirigir a SADE dominios existentes:
	##
	call centraliza_dominios;

	######
	# CONF-359 
	#
	
	if (req.url ~ "PURGE" || req.request == "PURGE") {
		if (client.ip ~ purge) {
			# =============================================
			# Se pasa solicitud de Purge desde URL a Request 
			set req.request = "PURGE";
			# Se quita PURGE de la URL
			set req.url = regsub(req.url, "\/PURGE", "");
			# =============================================
			return(lookup);
		}else{
			error 404 "Not allowed";
		}
	}
	
	######
	
	## CU-01:------------- Desde acá 
    if (req.http.host == "www.cepal.org") {
		set req.backend = sade;
		
		# Force client.ip forwarding
		remove req.http.X-Forwarded-For;
		set req.http.X-Forwarded-For = client.ip;
		
		## retorno con Pipe: No hace caché, cortocircuitea entre cliente y servidor
		return(pipe);
	## CU-01:------------- Hasta acá 
	} else {
		
		set req.backend = drupal;

		#  Use anonymous, cached pages if all backends are down.
		if (!req.backend.healthy) {
			#unset req.http.Cookie;
			error 755 "";
		}
		
		### Para conteo de emails abiertos por destinatarios
		### se elimina cache pasando directamente al servidor de backend
		if (req.http.host == "crm.cepal.org") {
			if (req.url ~ "^/sites/all/modules/civicrm/extern/*" ) {
				return (pass);
			}
		}
		### Fin CRM 

#		En caso de necesitar poner el sitio en mantenimiento
#		descomentar la linea siguiente (20141027 DdelMoral:
#
#		error 500 "Site under maintenance";

		# Allow the backend to serve up stale content if it is responding slowly.
		set req.grace = 600s;

		# Client IP is forwarded (instead of the) además del proxy 
		if (req.restarts == 0) {
			if (req.http.x-forwarded-for) {
				set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
			} else {
				set req.http.X-Forwarded-For = client.ip;
			}
		}
		 
		
		
		if (req.http.host ~ "conferenciaelac.cepal.org" 
				|| req.http.host ~ "crpd.cepal.org" 
				|| req.http.host ~ "crds.cepal.org" 
				|| req.http.host ~ "negociacionp10.cepal.org" 
				|| req.http.host ~ "cea.cepal.org" 
				|| req.http.host ~ "crp-ilpes.cepal.org" 
				|| req.http.host ~ "periododesesiones.cepal.org"
				|| req.http.host ~ "cdcc.cepal.org"
				|| req.http.host ~ "oig.cepal.org"
				|| req.http.host ~ "conferenciamujer.cepal.org"
				|| req.http.host ~ "innovalac.cepal.org"
				|| req.http.host ~ "foroalc2030.cepal.org"
				|| req.http.host ~ "crm.cepal.org"
				|| req.http.host ~ "observatoriop10.cepal.org"
                || req.http.host ~ "conferenciaenvejecimiento.cepal.org"
                || req.http.host ~ "observatoriosocial.cepal.org"
			) 	{
			call deny_admin_drupal;
		} else {
			# Do not cache these paths.
			if (req.url ~ "^/status\.php$" ||
				req.url ~ "^/update\.php$" ||
				req.url ~ "^/install\.php$" ||
				req.url ~ "^/admin$" ||
				req.url ~ "^/admin/.*$" ||
				req.url ~ "^/info/.*$" ||
				req.url ~ "^/flag/.*$" ||
				req.url ~ "^.*/ajax/.*$" ||
				req.url ~ "^.*/ahah/.*$") { 
				return (pass);
			}
		}

		# Do not allow outside access to cron.php or install.php.
		#if (req.url ~ "^/(cron|install)\.php$" && !client.ip ~ internal) {
		if (req.url ~ "^/(cron|install)\.php$" ) {
			# Have Varnish throw the error directly.
			error 404 "Page not found.";
			# Use a custom error page that you've defined in Drupal at the path "404".
			# set req.url = "/404";
		}

		if (req.url ~ "^/(user|users)/.*$" ) {
			error 404 "Page not found.";
		}

		 
		# Always cache the following file types for all users. This list of extensions
		# appears twice, once here and again in vcl_fetch so make sure you edit both
		# and keep them equal.
		if (req.url ~ "(?i)\.(pdf|asc|dat|txt|doc|docx|xls|ppt|tgz|csv|png|gif|jpeg|jpg|ico|swf|css|js)(\?.*)?$") {
			unset req.http.Cookie;
		}
		 
		# Remove all cookies that Drupal doesn't need to know about. We explicitly
		# list the ones that Drupal does need, the SESS and NO_CACHE. If, after
		# running this code we find that either of these two cookies remains, we
		# will pass as the page cannot be cached.
		if (req.http.Cookie) {
			set req.http.Cookie = ";" + req.http.Cookie;
			set req.http.Cookie = regsuball(req.http.Cookie, "; +", ";");   
			set req.http.Cookie = regsuball(req.http.Cookie, ";(S{1,2}ESS[a-z0-9]+|NO_CACHE|context_breakpoints)=", "; \1=");
			set req.http.Cookie = regsuball(req.http.Cookie, ";[^ ][^;]*", "");
			set req.http.Cookie = regsuball(req.http.Cookie, "^[; ]+|[; ]+$", "");

			if (req.http.Cookie == "") {
				# If there are no remaining cookies, remove the cookie header. If there
				# aren't any cookie headers, Varnish's default behavior will be to cache
				# the page.
				unset req.http.Cookie;
			} else {
				# If there is any cookies left (a session or NO_CACHE cookie), do not
				# cache the page. Pass it on to Apache directly.
				return (pass);
			}
		}
	}
}
sub vcl_hit { 
	if (req.request == "PURGE") {
        purge;
        error 204 "Purged";
    }
}

sub vcl_miss{
	if (req.request == "PURGE") {
        purge;
        error 204 "Purged (Not in cache)";
    }
 }
 
# Set a header to track a cache HIT/MISS.
sub vcl_deliver {
	if (obj.hits > 0) {
		set resp.http.X-Varnish-Cache = "HIT";
	} else {
		set resp.http.X-Varnish-Cache = "MISS";
	}
}
 
# Code determining what to do when serving items from the Apache servers.
# beresp == Back-end response from the web server.
sub vcl_fetch {
	# We need this to cache 404s, 301s, 500s. Otherwise, depending on backend but
	# definitely in Drupal's case these responses are not cacheable by default.
	if (beresp.status == 404 || beresp.status == 301 || beresp.status == 500) {
		set beresp.ttl = 10m;
	}

	# Don't allow static files to set cookies.
	# (?i) denotes case insensitive in PCRE (perl compatible regular expressions).
	# This list of extensions appears twice, once here and again in vcl_recv so
	# make sure you edit both and keep them equal.
	if (req.url ~ "(?i)\.(pdf|asc|dat|txt|doc|docx|xls|ppt|tgz|csv|png|gif|jpeg|jpg|ico|swf|ccs|js)(\?.*)?$") {
		unset beresp.http.set-cookie;
	}

	# Allow items to be stale if needed.
	set beresp.grace = 600s;
}
 
# In the event of an error, show friendlier messages.
sub vcl_error {

	# En caso de mantenimiento forzado a estos sitios residentes en apache2-p2
	# 20141027 by DdelMoral & Javier Pi

     if ( (obj.status == 755) && (req.http.host ~ "prebisch.cepal.org" || req.http.host ~ "prebisch.eclac.org" || req.http.host ~ "periododesesiones.cepal.org"  || req.http.host ~ "caribbeantest.eclac.org" )) {
		# if (req.http.host ~ "prebisch.cepal.org" || req.http.host ~ "prebisch.eclac.org" || req.http.host ~ "periododesesiones.cepal.org" ) {
		set obj.status = 500;
        set obj.http.Content-Type = "text/html; charset=utf-8";
        synthetic std.fileread("/etc/varnish/maintenance.html");
        return (deliver);
    }


	## 
	# CU-01: Reescribir dominio. www.cepal.cl, www.eclac.cl y www.eclac.org se redireccionan a www.cepal.org
	## CU-01:------------- Desde acá 
	if (obj.status == 750) {
		set obj.http.Location = obj.response;
        #HTTP 301 para indicar redirección permanente
        set obj.status = 301;
        return(deliver);
    }
	## CU-01:------------- Hasta acá 
	
	## 
	# CU-02: Reescribir dominio. 
	# socinfo.cepal.org
	# www.ilpes.cl
	# www.ofilac.org
	# www.eclacpos.org
	# www.cepal.org.mx
	## CU-02:------------- Desde acá 
	if (obj.status == 751) {
		set obj.http.Location = obj.response;
        #HTTP 302 para indicar redirección temporal - Así estaba en IIS
        set obj.status = 302;
        return(deliver);
    }
	## CU-02:------------- Hasta acá 
	## Acceso denegado. Han enviado URL que se ha programado no entregar.
	if (obj.status == 752) {
		# Acceso denegado  403;
		#call error_403;
		# Se cambia para no indicar que existe y está prohibido
		set obj.status = 404;
		#set obj.http.Content-Type = "text/html; charset=utf-8";
        #synthetic std.fileread("/etc/varnish/error404.html");
		 
		set obj.http.Content-Type = "text/html; charset=utf-8";
		synthetic {"
			<html>
			<head>
			  <title>404 Page not found</title>
			  <style>
				body { background: #303030; text-align: center; color: white; }
				#page { border: 1px solid #CCC; width: 500px; margin: 100px auto 0; padding: 30px; background: #323232; }
				a, a:link, a:visited { color: #CCC; }
				.error { color: #222; }
			  </style>
			</head>
			<body onload="setTimeout(function() { window.location = '/es' }, 5)">
			  <div id="page">
				<h1 class="title">Not found</h1>
				<p>.</p>
				<p> <a href="/">homepage</a> in 5 seconds.</p>
				<div class="error">(Error "} + obj.status + " " + obj.response + {")</div>
			  </div>
			</body>
			</html>
		"};
        return(deliver);
	}
	
	
	# Redirect to some other URL in the case of a homepage failure.
	if (req.url ~ "^/?$") {
		set obj.status = 302;
		set obj.http.Location = "http://www.cepal.org/";
	}
	# Otherwise redirect to the homepage, which will likely be in the cache.
	set obj.http.Content-Type = "text/html; charset=utf-8";
	synthetic {"
		<html>
			<head>
				<title>Page Unavailable</title>
				<style>
					body { background: #303030; text-align: center; color: white; }
					#page { border: 1px solid #CCC; width: 500px; margin: 100px auto 0; padding: 30px; background: #323232; }
					a, a:link, a:visited { color: #CCC; }
					.error { color: #222; }
				</style>
			</head>
			<body onload="setTimeout(function() { window.location = '/es' }, 5)">
				<div id="page">
					<h1 class="title">Page Unavailable</h1>
					<p>The page you requested is temporarily unavailable.</p>
					<p>We're redirecting you to the <a href="/">homepage</a> in 5 seconds.</p>
					<div class="error">(Error "} + obj.status + " " + obj.response + {")</div>
				</div>
			</body>
		</html>
	"};
	return (deliver);
}


sub vcl_pipe {
     # Note that only the first request to the backend will have
     # X-Forwarded-For set.  If you use X-Forwarded-For and want to
     # have it set for all requests, make sure to have:
     # set bereq.http.connection = "close";
     # here.  It is not set by default as it might break some broken web
     # applications, like IIS with NTLM authentication.
 
     set bereq.http.connection = "close";
     return (pipe);
 }


