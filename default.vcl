# NightBits (Jeroen Saey) Varnish 4.0 Configuration
vcl 4.0;

import std;
import directors;

backend server1 { # Our backend server
  .host = "127.0.0.1";    # IP or Hostname of backend
  .port = "7000";         # Port the backend is listening on
  .max_connections = 300;

  .probe = {
    #.url = "/"; # easy way (GET /)
    # I want some HEAD /
    .request =
      "HEAD / HTTP/1.1"
      "Host: localhost"
      "Connection: close"
      "User-Agent: NightBits Varnish Health Probe";

    .interval  = 5s; # check the health of each backend every 5 seconds
    .timeout   = 1s; # timing out after 1 second.
    .window    = 5;  # If 3 out of the last 5 polls succeeded the backend is considered healthy, otherwise it will be marked as sick
    .threshold = 3;
  }

  .first_byte_timeout     = 300s;   # How long to wait before we receive a first byte from our backend?
  .connect_timeout        = 5s;     # How long to wait for a backend connection?
  .between_bytes_timeout  = 2s;     # How long to wait between bytes received from our backend?
}

acl purgers {
  # ACL we'll use later to allow purges
  "localhost";
  "127.0.0.1";
  "::1";
}

acl forbidden {
# Spam IP Addresses or ranges to drop all traffic from.
    #"127.0.0.1";
}

acl allow_access {
  #ACL which gives special access to URLS
  "localhost";
  "127.0.0.1";
  "::1";
  "192.168.1.0"/32;
}

sub vcl_init {
  # Called when VCL is loaded, before any requests pass through it.
  # Typically used to initialize VMODs.

  new vdir = directors.round_robin();
  vdir.add_backend(server1);
}

sub removeHeaders{
   # Remove working headers that shoundn't be sent to the client.
    unset resp.http.X-Magento-Debug;
    unset resp.http.X-Magento-Tags;
    unset resp.http.X-Powered-By;
    unset resp.http.Server;
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    unset resp.http.Link;
    unset resp.http.X-Generator;

    unset resp.http.X-Req-Host;
    unset resp.http.X-Req-URL;
    unset resp.http.X-Req-URL-Base;

    set resp.http.Server = "NightBitsLAN";
    set resp.http.X-Powered-By = "CryptionBytes";
}

sub vcl_recv {
  # Called at the beginning of a request, after the complete request has been received and parsed.

  set req.backend_hint = vdir.backend(); # send all traffic to the vdir director

  # Normalize the header, remove the port
  set req.http.Host = regsub(req.http.Host, ":[0-9]+", "");

  # I dont want to see the varnish header ^^ we need to be secret
  unset req.http.proxy;

   # Set real client IP so Apache can log it
   if (! req.http.X-Forwarded-For) {
       set req.http.X-Forwarded-For = client.ip;
   }

   # Remove local proxy address from header
   if (req.http.X-Forwarded-For ~ "127\.0\.0\.1") {
       set req.http.X-Forwarded-For = regsuball(req.http.X-Forwarded-For, ", 127\.0\.0\.1", "");
   }

   # This is HTTP if it's not forwarded from nginx
   if (! req.http.X-Forwarded-Proto) {
       set req.http.X-Forwarded-Proto = "http";
       set req.http.X-Forwarded-Port = 80;
   }

  # Block access from these hosts
   if (client.ip ~ forbidden) {
       return (synth(403, "Forbidden"));
   }

   # Do something special with certain urls / ip addresses
   if (req.http.host ~ "(www\.)?tlw\.io" && !(client.ip ~ allow_access))
   {
       # We dont want to give access to these websites yet
       return (synth(403, "Access Denied"));
   }

  # Normalize the query arguments
  set req.url = std.querysort(req.url);

  # Allow purging
  if (req.method == "PURGE") {
       if (!req.http.X-Magento-Tags-Pattern) {
         if (!client.ip ~ purgers) {
            return (synth(405, "You are not allowed to purge"));
        }

            if (req.http.X-Purge-Method) {
                    if (req.http.X-Purge-Method ~ "(?i)regex") {
                            call purge_regex;
                    } elsif (req.http.X-Purge-Method ~ "(?i)exact") {
                            call purge_exact;
                    } else {
                            call purge_page;
                    }
            } else {
                    # No X-Purge-Method header was specified.
                    # Do our best to figure out which one they want.
                    if (req.url ~ "\.\*" || req.url ~ "^\^" || req.url ~ "\$$" || req.url ~ "\\[.?*+^$|()]") {
                            call purge_regex;
                    } elsif (req.url ~ "\?") {
                            call purge_exact;
                    } else {
                            call purge_page;
                    }
            }

            return(synth(200, "Purged."));
    }
    else {
       ban("obj.http.X-Magento-Tags ~ " + req.http.X-Magento-Tags-Pattern + " && obj.http.X-Req-Host == " + req.http.host);
       return (synth(200, "Purged"));
    }

  }

    # Force SSL Everywhere for listed domains.
   #if ( (req.http.host ~ "^(www.saey.me|saey.me|NightBits.lan)") && req.http.X-Forwarded-Proto !~ "https") {
    # Or switch to this like to fore SSL for all domains.
    #if (req.http.X-Forwarded-Proto !~ "https") {
    #    set req.http.x-redir = "https://" + req.http.host + req.url;
    #    return (synth(750, ""));
    #}

  # Only deal with "normal" types
  if (req.method != "GET" &&
      req.method != "HEAD" &&
      req.method != "PUT" &&
      req.method != "POST" &&
      req.method != "TRACE" &&
      req.method != "OPTIONS" &&
      req.method != "PATCH" &&
      req.method != "DELETE") {
    /* Non-RFC2616 or CONNECT WTF ?. */
    /*Why send the packet upstream, while a non-valid HTTP method is used? */
    return(synth(404, "That escalated quickly a Non-valid HTTP method!"));
  }

 # Websocket support
 if (req.http.Upgrade ~ "(?i)websocket") {
    return (pipe);
  }

  # Only cache GET or HEAD requests. This makes sure the POST requests are always passed.
  if (req.method != "GET" && req.method != "HEAD") {
    return (pass);
  }

 # Bypass shopping cart and checkout requests
    if (req.url ~ "^/(cart|my-account|checkout|addons)") {
        return (pass);
    }

 # Add a header to tell Apache backend to minify files in most cases (domains can be excluded from minification)
    if( (req.http.cookie !~ "minify=disable" && req.http.host !~ "^(www.blockddomain.com|blockeddomain2.com)") || req.http.cookie ~ "minify=force" )
    {
        # Block already minfied items and manually flaged items
        if(req.url !~ "(.min.js|.min.css)") { # Add script or css filenames to manually exclude here seperated by |'s
            set req.http.x-minify = "js,css,html"; # Tell apache what resources to minify
        }
    }

  # Some generic URL manipulations
  # First remove the Google Analytics added parameters, useless for our backend

  if (req.url ~ "(\?|&)(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=") {
    set req.url = regsuball(req.url, "&(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "");
    set req.url = regsuball(req.url, "\?(utm_source|utm_medium|utm_campaign|utm_content|gclid|cx|ie|cof|siteurl)=([A-z0-9_\-\.%25]+)", "?");
    set req.url = regsub(req.url, "\?&", "?");
    set req.url = regsub(req.url, "\?$", "");
  }

  # Custom Scripts
   if (req.url ~ "/api/") {
       # Don't cache, pass to backend
       return (pass);
   }

  # Strip hash, server doesn't need it.
  if (req.url ~ "\#") {
    set req.url = regsub(req.url, "\#.*$", "");
  }

  # Strip a trailing ? if it exists
  if (req.url ~ "\?$") {
    set req.url = regsub(req.url, "\?$", "");
  }

  # Some generic cookie manipulations
  # Remove the "has_js" cookie
  set req.http.Cookie = regsuball(req.http.Cookie, "has_js=[^;]+(; )?", "");

  # Remove DoubleClick offensive cookies
  set req.http.Cookie = regsuball(req.http.Cookie, "__gads=[^;]+(; )?", "");

  # Remove the Quant Capital cookies (added by some plugin, all __qca)
  set req.http.Cookie = regsuball(req.http.Cookie, "__qc.=[^;]+(; )?", "");

  # Remove the AddThis cookies
  set req.http.Cookie = regsuball(req.http.Cookie, "__atuv.=[^;]+(; )?", "");

  # Remove a ";" prefix in the cookie if present
  set req.http.Cookie = regsuball(req.http.Cookie, "^;\s*", "");

  # Remove any Google Analytics based cookies
  set req.http.Cookie = regsuball(req.http.Cookie, "__utm.=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "_ga=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "_gat=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "utmctr=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "utmcmd.=[^;]+(; )?", "");
  set req.http.Cookie = regsuball(req.http.Cookie, "utmccn.=[^;]+(; )?", "");

  # Are there cookies left with only spaces or that are empty?
  if (req.http.cookie ~ "^\s*$") {
    unset req.http.cookie;
  }

  if (req.http.Cache-Control ~ "(?i)no-cache") {

  if (! (req.http.Via || req.http.User-Agent ~ "(?i)bot" || req.http.X-Purge)) {
      return(purge);
    }
  }

  # static files are always cacheable. remove SSL flag and cookie
    if (req.url ~ "^/(pub/)?(media|static)/.*\.(ico|css|js|jpg|jpeg|png|gif|tiff|bmp|mp3|ogg|svg|swf|woff|woff2|eot|ttf|otf)$") {
        unset req.http.Https;
        unset req.http.Cookie;
    }

  # Large static files are delivered directly to the end-user without
  # waiting for Varnish to fully read the file first.
  # (for streaming youtube or such)
  if (req.url ~ "^[^?]*\.(7z|avi|bz2|flac|flv|gz|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|ogm|opus|rar|tar|tgz|tbz|txz|wav|webm|xz|zip)(\?.*)?$") {
    unset req.http.Cookie;
    return (hash);
  }

  # Remove all cookies for static files
  if (req.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
    unset req.http.Cookie;
    return (hash);
  }

  # Send Surrogate-Capability headers to announce ESI support to backend
  set req.http.Surrogate-Capability = "key=ESI/1.0";

  if (req.http.Authorization) {
    # Not cacheable by default
    return (pass);
  }

  return (hash);
}


sub vcl_hit {
    if (req.method == "PURGE"){
        return(synth(200, "Varnish cache has been purged for this object."));
    }
}

sub vcl_miss {
    if (req.method == "PURGE") {
        return(synth(404, "Object not in cache."));
    }
}

sub vcl_pipe {
  # Called upon entering pipe mode.
  # In this mode, the request is passed on to the backend, and any further data from both the client
  # and backend is passed on unaltered until either end closes the connection. Basically, Varnish will
  # degrade into a simple TCP proxy, shuffling bytes back and forth. For a connection in pipe mode,
  # no other VCL subroutine will ever get called after vcl_pipe.

  # support websockets and http upgrade
  if (req.http.upgrade) {
    set bereq.http.upgrade = req.http.upgrade;
  }

  return (pipe);
}

sub vcl_pass {
  # Called upon entering pass mode. In this mode, the request is passed on to the backend, and the
  # backend's response is passed on to the client, but is not entered into the cache. Subsequent
  # requests submitted over the same client connection are handled normally.

  # return (pass);
}

# The data on which the hashing will take place
sub vcl_hash {
  # Called after vcl_recv to create a hash value for the request. This is used as a key
  # to look up the object in Varnish.

  if (req.http.cookie ~ "X-Magento-Vary=") {
        hash_data(regsub(req.http.cookie, "^.*?X-Magento-Vary=([^;]+);*.*$", "\1"));
    }

  hash_data(req.url);

  if (req.http.host) {
    hash_data(req.http.host);
  } else {
    hash_data(server.ip);
  }

  # hash cookies for requests that have them
  if (req.http.Cookie) {
    hash_data(req.http.Cookie);
  }
}

sub vcl_hit {
  # Called when a cache lookup is successful.

  if (obj.ttl >= 0s) {
    return (deliver);
  }

  # When several clients are requesting the same page Varnish will send one request to the backend and place the others on hold while fetching one copy from the backend. In some products this is called request coalescing and Varnish does this automatically.
  # Spongebob choose this way because he wanted to have fast response times

 if (!std.healthy(req.backend_hint) && (obj.ttl + obj.grace > 0s)) {
   return (deliver);
 } else {
   return (fetch);
 }

  # We cannot find any cooked objects to we need to cook some ourself.
  if (std.healthy(req.backend_hint)) {
    # Backend is healthy. Limit age to 10s.
    if (obj.ttl + 10s > 0s) {
      #set req.http.grace = "normal(limited)";
      return (deliver);
    } else {
      # No candidate for grace. Fetch a fresh object.
      return(fetch);
    }
  } else {
    # backend is sick - use full grace
      if (obj.ttl + obj.grace > 0s) {
      #set req.http.grace = "full";
      return (deliver);
    } else {
      # no graced object.
      return (fetch);
    }
  }

  # fetch & deliver once we get the result
  return (fetch); # Dead code even exists ! :D
}

sub vcl_miss {
  # Called after a cache lookup if the requested document was not found in the cache. Its purpose
  # is to decide whether or not to attempt to retrieve the document from the backend, and which
  # backend to use.

  return (fetch);
}

# Handle the HTTP request coming from our backend
sub vcl_backend_response {
  # Called after the response headers has been successfully retrieved from the backend.

  # Ignore Set-Cookie headers on non-cart/profile/logged in pages where client really doenst need cookie set.
  if(bereq.url !~ "/(cart|my-account|checkout|addons|shop)" && bereq.http.X-Proxy-Proto !~ "HTTPS" && bereq.method ~ "GET" ) {
        unset beresp.http.set-cookie;
  }

 # Ensure items are properly compressed.
    if (bereq.url ~ "\.js$" || beresp.http.content-type ~ "text") {
        set beresp.do_gzip = true;
    }

  # Pause ESI request and remove Surrogate-Control header
  if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
    unset beresp.http.Surrogate-Control;
    set beresp.do_esi = true;
  }

   set beresp.http.X-Req-Host = bereq.http.host;
   set beresp.http.X-Req-URL = bereq.url;
   set beresp.http.X-Req-URL-Base = regsub(bereq.url, "\?.*$", "");

  # Enable cache for all static files
  if (bereq.url ~ "^[^?]*\.(7z|avi|bmp|bz2|css|csv|doc|docx|eot|flac|flv|gif|gz|ico|jpeg|jpg|js|less|mka|mkv|mov|mp3|mp4|mpeg|mpg|odt|otf|ogg|ogm|opus|pdf|png|ppt|pptx|rar|rtf|svg|svgz|swf|tar|tbz|tgz|ttf|txt|txz|wav|webm|webp|woff|woff2|xls|xlsx|xml|xz|zip)(\?.*)?$") {
    unset beresp.http.set-cookie;
  }

  # Large static files are delivered directly to the end-user without
  # waiting for Varnish to fully read the file first.
  # (for youtube streaming or such)
  if (bereq.url ~ "^[^?]*\.(7z|avi|bz2|flac|flv|gz|mka|mkv|mov|mp3|mp4|mpeg|mpg|ogg|ogm|opus|rar|tar|tgz|tbz|txz|wav|webm|xz|zip)(\?.*)?$") {
    unset beresp.http.set-cookie;
  }

  # Sometimes, a 301 or 302 redirect formed via Apache's mod_rewrite can mess with the HTTP port that is being passed along.
  # This often happens with simple rewrite rules in a scenario where Varnish runs on :80 and Apache on :8080 on the same box.
  # A redirect can then often redirect the end-user to a URL on :8080, where it should be :80.
  # To prevent accidental replace, we only filter the 301/302 redirects for now.
  if (beresp.status == 301 || beresp.status == 302) {
    set beresp.http.Location = regsub(beresp.http.Location, ":[0-9]+", "");
  }

  # validate if we need to cache it and prevent from setting cookie
    # images, css and js are cacheable by default so we have to remove cookie also
    if (beresp.ttl > 0s && (bereq.method == "GET" || bereq.method == "HEAD")) {
        unset beresp.http.set-cookie;
        if (bereq.url !~ "\.(ico|css|js|jpg|jpeg|png|gif|tiff|bmp|gz|tgz|bz2|tbz|mp3|ogg|svg|swf|woff|woff2|eot|ttf|otf)(\?|$)") {
            set beresp.http.Pragma = "no-cache";
            set beresp.http.Expires = "-1";
            set beresp.http.Cache-Control = "no-store, no-cache, must-revalidate, max-age=0";
            set beresp.grace = 1m;
        }
    }

  if (beresp.http.X-Magento-Debug) {
        set beresp.http.X-Magento-Cache-Control = beresp.http.Cache-Control;
    }

  # If page is not cacheable then bypass varnish for 2 minutes as Hit-For-Pass
    if (beresp.ttl <= 0s ||
        beresp.http.Surrogate-control ~ "no-store" ||
        (!beresp.http.Surrogate-Control && beresp.http.Vary == "*")) {
        # Mark as Hit-For-Pass for the next 2 minutes
        set beresp.ttl = 120s;
        set beresp.uncacheable = true;
    }

  # Allow stale content, in case the backend goes down.
  # make Varnish keep all objects for 6 hours beyond their TTL
  set beresp.grace = 6h;

  return (deliver);
}

# Regex purging
# Treat the request URL as a regular expression.
sub purge_regex {
        ban("obj.http.X-Req-URL ~ " + req.url + " && obj.http.X-Req-Host == " + req.http.host);
}

# Exact purging
# Use the exact request URL (including any query params)
sub purge_exact {
        ban("obj.http.X-Req-URL == " + req.url + " && obj.http.X-Req-Host == " + req.http.host);
}

# Page purging (default)
# Use the exact request URL, but ignore any query params
sub purge_page {
        set req.url = regsub(req.url, "\?.*$", "");
        ban("obj.http.X-Req-URL-Base == " + req.url + " && obj.http.X-Req-Host == " + req.http.host);
}

# The routine when we deliver the HTTP request to the user
# Last chance to modify headers that are sent to the client
sub vcl_deliver {
  # Called before a cached object is delivered to the client.

  if (resp.http.X-Magento-Debug) {
        if (resp.http.x-varnish ~ " ") {
            set resp.http.X-Magento-Cache-Debug = "HIT";
        } else {
            set resp.http.X-Magento-Cache-Debug = "MISS";
        }
    } else {
        unset resp.http.Age;
    }

  if (resp.http.X-Varnish ~ "[0-9]+ +[0-9]+") {
    set resp.http.X-Cache = "HIT";
  } else {
    set resp.http.X-Cache = "MISS";
  }

  call removeHeaders;
  return (deliver);
}

sub vcl_purge {
  # Only handle actual PURGE HTTP methods, everything else is discarded
  if (req.method != "PURGE") {
    # restart request
    set req.http.X-Purge = "Yes";
    return(restart);
  }
}

sub vcl_synth {
  if (resp.status == 720) {
    # We use this special error status 720 to force redirects with 301 (permanent) redirects
    # To use this, call the following from anywhere in vcl_recv: return (synth(720, "http://host/new.html"));
    set resp.http.Location = resp.reason;
    set resp.status = 301;
    return (deliver);
  } elseif (resp.status == 721) {
    # And we use error status 721 to force redirects with a 302 (temporary) redirect
    # To use this, call the following from anywhere in vcl_recv: return (synth(720, "http://NightBits.me/mypage.html"));
    set resp.http.Location = resp.reason;
    set resp.status = 302;
    return (deliver);
  } elseif (resp.status == 750) {
    set resp.status = 301;
    set resp.http.Location = req.http.x-redir;
    return (deliver);
  }

  return (deliver);
}


sub vcl_fini {
  # Called when VCL is discarded only after all requests have exited the VCL.
  # Typically used to clean up VMODs.

  return (ok);
}
