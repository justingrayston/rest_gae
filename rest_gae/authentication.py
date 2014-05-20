"""
	rest_gae Authentication Class
"""

# The REST permissions
PERMISSION_ANYONE = 'anyone'
PERMISSION_LOGGED_IN_USER = 'logged_in_user'
PERMISSION_OWNER_USER = 'owner_user'
PERMISSION_ADMIN = 'admin'


class BaseAuthentication(object):
	'''
		Abstract authentication class
		TODO: (JG) DOCUMENT
	'''
	@classmethod
	def get_default_permission(cls):
		'''
			Gets the default permission value, normally that is public
		'''
		raise NotImplementedError('get_default_permission not implemented')

	@classmethod
	def get_restricted_permissions_list(cls):
		'''
			Should return a list of all the restricted permissions list for Easy
			permission in restricted tests
		'''
		raise NotImplementedError('get_restricted_permissions_list not implemented')

	@classmethod
	def validate_arguments(cls):
		'''
			Validates meta values on the model itself
		'''
		raise NotImplementedError('validate_arguments not implemented')

	@classmethod
	def verify_permission(cls):
		'''
			Should verify the permission value to the request
		'''
		raise NotImplementedError("verify_permission not implemented")

	@classmethod
	def user_has_access_to_model(cls):
		'''
			The current user can access the model right?
		'''
		raise NotImplementedError('user_has_access_to_model not implemented')

	@classmethod
	def filter_by_access(cls):
		'''
			filter results (ndb.Query) by access
		'''
		raise NotImplementedError('filter_by_access not implemented')



class DefaultAuthentication(BaseAuthentication):
	permission_anyone = 'anyone'
	permission_logged_in_user = 'logged_in_user'
	permission_owner_user = 'owner_user'
	permission_admin = 'admin'

	@classmethod
	def get_default_permission(cls):
		return {'OPTION' : cls.permission_anyone}

	@classmethod
	def get_restricted_permissions_list(cls):
		return [
			cls.permission_logged_in_user,
			cls.permission_owner_user,
			cls.permission_admin
		]

	@classmethod
	def validate_arguments(cls, model, permissions):
		'''
			Validate arguments (we do this at this stage in order to raise exceptions immediately 
			rather than while the app is running)
		'''

		if cls.permission_owner_user in permissions.values():
		    if not hasattr(model, 'RESTMeta') or not hasattr(model.RESTMeta, 'user_owner_property'):
		    	msg = 'Must define a RESTMeta.user_owner_property for the model class %s if user-owner permission is used'
		        raise ValueError(msg % (model))
		    if not hasattr(model, model.RESTMeta.user_owner_property):
		    	msg = '''The user_owner_property "%s" (defined in RESTMeta.user_owner_property) 
		    			does not exist in the given model %s'''
		        raise ValueError(msg % (model.RESTMeta.user_owner_property, model))



	@classmethod
	def verify_permission(cls, permission, rest_handler):
		'''
			Verifies the permissions, 
			ARGS: 
				permission: (string) the permission to check against
				rest_handler: (object) RestHandler class instance 
		'''

		if permission in cls.get_restricted_permissions_list() and not rest_handler.user:
			# User not logged-in as required		
			return False, rest_handler.unauthorized
		elif permission == cls.permission_admin and not rest_handler.is_user_admin:
		    # User is not an admin
		    return False, rest_handler.permission_denied

		return True, None

	@classmethod
	def user_has_access_to_model(cls, permission, model, rest_handler):
		'''
			Vefiry the user has access to model
		'''
		if (permission == cls.permission_owner_user) and (rest_handler.get_model_owner(model) != rest_handler.user.key):
			# The currently logged-in user is not the owner of the model
			return rest_handler.permission_denied()

	@classmethod
	def filter_by_access(cls, method, rest_handler, query=None):
		if not query:
			query = rest_handler.model.query()
		if rest_handler.permissions[method] == cls.permission_owner_user:
			# Return only models owned by currently logged-in user
			return query.filter(getattr(rest_handler.model, rest_handler.user_owner_property) == rest_handler.user.key)

		return query
