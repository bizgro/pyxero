from __future__ import unicode_literals

import os
import requests
import six

from six.moves.urllib.parse import parse_qs

from .constants import XERO_PROJECTS_URL
from .exceptions import (
    XeroBadRequest, XeroExceptionUnknown, XeroForbidden, XeroInternalError,
    XeroNotAvailable, XeroNotFound, XeroNotImplemented, XeroRateLimitExceeded,
    XeroUnauthorized, XeroUnsupportedMediaType
)


class ProjectsManager(object):
	DECORATED_METHODS = (
		'get',
		'all',
		'filter',
		'create',
		'save',
		'delete',
		'add_time',
		'get_tasks',
		'get_content',
		)
	DATETIME_FIELDS = (
		'UpdatedDateUTC',
		'Updated',
		'FullyPaidOnDate',
		'DateTimeUTC',
		'CreatedDateUTC'
	)
	DATE_FIELDS = (
		'DueDate',
		'Date',
		'PaymentDate',
		'StartDate',
		'EndDate',
		'PeriodLockDate',
		'DateOfBirth',
		'OpeningBalanceDate',
		'PaymentDueDate',
		'ReportingDate',
		'DeliveryDate',
		'ExpectedArrivalDate',
	)
	BOOLEAN_FIELDS = (
		'IsSupplier',
		'IsCustomer',
		'IsDemoCompany',
		'PaysTax',
		'IsAuthorisedToApproveTimesheets',
		'IsAuthorisedToApproveLeave',
		'HasHELPDebt',
		'AustralianResidentForTaxPurposes',
		'TaxFreeThresholdClaimed',
		'HasSFSSDebt',
		'EligibleToReceiveLeaveLoading',
		'IsExemptFromTax',
		'IsExemptFromSuper',
		'SentToContact',
		'IsSubscriber',
		'HasAttachments',
		'ShowOnCashBasisReports',
		'IncludeInEmails',
		'SentToContact',
		'CanApplyToRevenue',
		'IsReconciled',
		'EnablePaymentsToAccount',
		'ShowInExpenseClaims'
	)
	OPERATOR_MAPPINGS = {
		'gt': '>',
		'lt': '<',
		'lte': '<=',
		'gte': '>=',
		'ne': '!='
	}
	def __init__(self, name, credentials, user_agent=None):
		from xero import __version__ as VERSION
		self.credentials = credentials
		self.name = name
		self.base_url = credentials.base_url + XERO_PROJECTS_URL

		if user_agent is None:
			self.user_agent = 'pyxero/%s ' % VERSION + requests.utils.default_user_agent()
		else:
			self.user_agent = user_agent

		for method_name in self.DECORATED_METHODS:
			method = getattr(self, '_%s' % method_name)
			setattr(self, method_name, self._get_data(method))

	def _get_results(self, data):
		response = data['Response']
		if self.name in response:
			result = response[self.name]
		elif 'Attachments' in response:
			result = response['Attachments']
		else:
			return None

		if isinstance(result, tuple) or isinstance(result, list):
			return result

		if isinstance(result, dict) and self.singular in result:
			return result[self.singular]
		
	def _get_data(self, func):
		""" This is the decorator for our DECORATED_METHODS.
		Each of the decorated methods must return:
			uri, params, method, body, headers, singleobject
		"""
		def wrapper(*args, **kwargs):
			timeout = kwargs.pop('timeout', None)

			uri, params, method, body, headers, singleobject = func(*args, **kwargs)

			if headers is None:
				headers = {}

			# Use the JSON API by default, but remember we might request a PDF (application/pdf)
			# so don't force the Accept header.
			if 'Accept' not in headers:
				headers['Accept'] = 'application/json'

			# Set a user-agent so Xero knows the traffic is coming from pyxero
			# or individual user/partner
			headers['User-Agent'] = self.user_agent
			
			response = getattr(requests, method)(
					uri, data=body, headers=headers, auth=self.credentials.oauth,
					params=params, timeout=timeout)

			if response.status_code == 200:
				if response.headers['content-type'].startswith('application/json'):
					return response.json()
				else:
					# return a byte string without doing any Unicode conversions
					return response.content

			elif response.status_code == 204:
				return response.content

			elif response.status_code == 400:
				raise XeroBadRequest(response)

			elif response.status_code == 401:
				raise XeroUnauthorized(response)

			elif response.status_code == 403:
				raise XeroForbidden(response)

			elif response.status_code == 404:
				raise XeroNotFound(response)

			elif response.status_code == 500:
				raise XeroInternalError(response)

			elif response.status_code == 501:
				raise XeroNotImplemented(response)

			elif response.status_code == 503:
				# Two 503 responses are possible. Rate limit errors
				# return encoded content; offline errors don't.
				# If you parse the response text and there's nothing
				# encoded, it must be a not-available error.
				payload = parse_qs(response.text)
				if payload:
					raise XeroRateLimitExceeded(response, payload)
				else:
					raise XeroNotAvailable(response)
			else:
				raise XeroExceptionUnknown(response)

		return wrapper

	def _get(self, id, headers=None):
		uri = '/'.join([self.base_url, self.name, id])
		return uri, {}, 'get', None, headers, True

	def _get_tasks(self, id):
		uri = '/'.join([self.base_url, self.name, id, 'Tasks']) + '/'
		return uri, {}, 'get', None, None, False

	def create_or_save(self, data, method='post', headers=None, summarize_errors=True):
		if not "Id" in data:
			uri = '/'.join([self.base_url, self.name])
		else:
			uri = '/'.join([self.base_url, self.name, data["Id"]])
		body = data
		if summarize_errors:
			params = {}
		else:
			params = {'summarizeErrors': 'false'}
		return uri, params, method, body, headers, False

	def _add_time(self, data, id):
		uri = '/'.join([self.base_url, self.name, id, 'time']) + '/'
		return uri, {}, 'post', data, None, False

	def _create(self, data):
		return self.create_or_save(data, method='post')

	def _save(self, data, summarize_errors=True):
		return self.create_or_save(data, method='put', summarize_errors=summarize_errors)

	def _delete(self, id):
		uri = '/'.join([self.base_url, self.name, id])
		return uri, {}, 'delete', None, None, False

	def _get_content(self, fileId):
		uri = '/'.join([self.base_url, self.name, fileId, "Content"])
		return uri, {}, 'get', None, None, False

	def prepare_filtering_date(self, val):
		if isinstance(val, datetime):
			val = val.strftime('%a, %d %b %Y %H:%M:%S GMT')
		else:
			val = '"%s"' % val
		return {'If-Modified-Since': val}
	
	def _filter(self, **kwargs):
		params = {}
		headers = None
		uri = '/'.join([self.base_url, self.name])

		if kwargs:
			if 'since' in kwargs:
				val = kwargs['since']
				headers = self.prepare_filtering_date(val)
				del kwargs['since']

			def get_filter_params(key, value):
				last_key = key.split('_')[-1]
				if last_key.upper().endswith('ID'):
					return 'Guid("%s")' % six.text_type(value)
				if key in self.BOOLEAN_FIELDS:
					return 'true' if value else 'false'
				elif key in self.DATE_FIELDS:
					return 'DateTime(%s,%s,%s)' % (value.year, value.month, value.day)
				elif key in self.DATETIME_FIELDS:
					return value.isoformat()
				else:
					return '"%s"' % six.text_type(value)

			def generate_param(key, value):
				parts = key.split("__")
				field = key.replace('_', '.')
				fmt = '%s==%s'
				if len(parts) == 2:
					# support filters:
					# Name__Contains=John becomes Name.Contains("John")
					if parts[1] in ["contains", "startswith", "endswith"]:
						field = parts[0]
						fmt = ''.join(['%s.', parts[1], '(%s)'])
					elif parts[1] in self.OPERATOR_MAPPINGS:
						field = parts[0]
						key = field
						fmt = '%s' + self.OPERATOR_MAPPINGS[parts[1]] + '%s'
					elif parts[1] in ["isnull"]:
						sign = '=' if value else '!'
						return '%s%s=null' % (parts[0], sign)
					field = field.replace('_', '.')
				return fmt % (
					field,
					get_filter_params(key, value)
				)

			# Move any known parameter names to the query string
			KNOWN_PARAMETERS = ['order', 'offset', 'page', 'includeArchived']
			for param in KNOWN_PARAMETERS:
				if param in kwargs:
					params[param] = kwargs.pop(param)

			filter_params = []

			if 'raw' in kwargs:
				raw = kwargs.pop('raw')
				filter_params.append(raw)

			# Treat any remaining arguments as filter predicates
			# Xero will break if you search without a check for null in the first position:
			# http://developer.xero.com/documentation/getting-started/http-requests-and-responses/#title3
			sortedkwargs = sorted(six.iteritems(kwargs),
				key=lambda item: -1 if 'isnull' in item[0] else 0)
			for key, value in sortedkwargs:
				filter_params.append(generate_param(key, value))

			if filter_params:
				params['where'] = '&&'.join(filter_params)

		return uri, params, 'get', None, headers, False
		
	def _all(self):
		uri = '/'.join([self.base_url, self.name])
		return uri, {}, 'get', None, None, False