sub deny_admin_drupal{
# Do not allow outside access to cron.php or install.php.
	if (
		std.tolower(req.url) ~ "^/cron\.php$"  ||
		std.tolower(req.url) ~ "^/status\.php$" ||
		std.tolower(req.url) ~ "^/update\.php$" ||
		std.tolower(req.url) ~ "^/install\.php$" ||
		
		std.tolower(req.url) ~ "^/admin$" ||
		std.tolower(req.url) ~ "^/admin/.*$" ||
		std.tolower(req.url) ~ "^/es\/admin*$" ||
		std.tolower(req.url) ~ "^/en\/admin*$" ||
		
		# Agregados luego de ver el contenido del archivo robots.txt de Drupal
		# Tienen que ver con http://apache2-q3:8080/browse/SWDEV-1396
		std.tolower(req.url) ~ "/scripts/" ||
		std.tolower(req.url) ~ "changelog.txt" ||
		std.tolower(req.url) ~ "install.mysql.txt" ||
		std.tolower(req.url) ~ "install.pgsql.txt" ||
		std.tolower(req.url) ~ "install.sqlite.txt" ||
		std.tolower(req.url) ~ "install.txt" ||
		std.tolower(req.url) ~ "license.txt" ||
		std.tolower(req.url) ~ "maintainers.txt" ||
		std.tolower(req.url) ~ "upgrade.txt" ||
		std.tolower(req.url) ~ "xmlrpc.php" ||
		std.tolower(req.url) ~ "/filter/tips/" ||
		std.tolower(req.url) ~ "/user/login/" ||
		std.tolower(req.url) ~ "/user/password/" ||
		std.tolower(req.url) ~ "/user/logout/" ||
		std.tolower(req.url) ~ "/?q=admin/" ||
		std.tolower(req.url) ~ "/?q=node/add/" ||
		std.tolower(req.url) ~ "/?q=comment/reply/" ||
		std.tolower(req.url) ~ "/?q=filter/tips/" ||
		std.tolower(req.url) ~ "/?q=user/password/" ||
		std.tolower(req.url) ~ "/?q=user/register/" ||
		std.tolower(req.url) ~ "/?q=user/login/" ||
		std.tolower(req.url) ~ "/?q=user/logout/" ||
		std.tolower(req.url) ~ "/?q=user" ||
		# Hasta acá las incorporaciones
		
		std.tolower(req.url) ~ "^/user$" ||
		std.tolower(req.url) ~ "^/es\/user$" ||
		std.tolower(req.url) ~ "^/en\/user$" ||
		
		std.tolower(req.url) ~ "^/update\.php$" ||
		
		std.tolower(req.url) ~ "^/node\/add$" ||
		std.tolower(req.url) ~ "^/es\/node\/add$" ||
		std.tolower(req.url) ~ "^/en\/node\/add$" ||
		
		
		std.tolower(req.url) ~ "^/opcache/.*$" ||
		std.tolower(req.url) ~ "^/info/.*$" ||
		std.tolower(req.url) ~ "^/flag/.*$" ||
		
		## Por ataque 24-04-15
		std.tolower(req.url) ~ "/?q=.*$"	|| 
		std.tolower(req.url) ~ "/user.*$" 	||
		std.tolower(req.url) ~ "/admin.*$"  || 
		std.tolower(req.url) ~ "/node\/add.*$" 
	){
	#error 404 "Not found.";
	# Se evi
	# error 752 "";
	## set req.url = "/404/" + req.url ;
	# 
	set req.url = "/";
	}
}