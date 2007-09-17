<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
		<meta name="layout" content="main" />
		<title>Login</title>

	</head>
	<body>
		<div id="login">
			<g:if test="${flash.message}">
				<div class="login_message">${flash.message}</div>
			</g:if>
			<div class="fheader">Please Login..</div>
			<form action="../j_acegi_security_check" method="POST" id="loginForm" class="cssform">
				<p>
					<label for="j_username">Login ID</label>
					<input type='text' class="text_" name='j_username' value='' />
				</p>
				<p>
					<label for="j_password">Password</label>
					<input type='password' class="text_" name='j_password' value='' />
				</p>
				<p>
					<input type="submit" value="Login" />
				</p>
			</form>
			<script type="text/javascript" language="JavaScript">
			  <!--
			  var focusControl = document.forms["loginForm"].elements["j_username"];
			  if (focusControl.type != "hidden" && !focusControl.disabled) {
			     focusControl.focus();
			  }
			  // -->
			</script>
		</div>
	</body>
</html>