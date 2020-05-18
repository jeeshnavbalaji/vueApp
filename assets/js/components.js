var esDomainIndex = "logstash-domain";
var esPacketIndex = "logstash-packet";
var esSystemIndex = "logstash-system";
var esAuditIndex = "logstash-audit";
var serviceApiUrl = location.protocol+"//"+location.hostname+":1468/api";
var host = location.protocol+"//"+location.hostname+":9200/";
var esDomainURL = host+esDomainIndex+"/_search";
var esPacketURL = host+esPacketIndex+"/_search";
var esSystemURL = host+esSystemIndex+"/_search";
var esAuditURL = host+esAuditIndex+"/_search";
var esURL = "";
var GMCUrl = "https://gmc.banduracyber.com/api/v1"
var setURL = function (type) {
	tableData.from=0;
	  tableData.pageSize= 20;
	  tableData.oldDocs='asc';
	  tableData.newDocs= 'desc';
	  tableData.dateQueryString='';
	  tableData.domainQueryString='';
	  tableData.protoQueryString='all';
	  tableData.sourceQueryString='';
	  tableData.destinationQueryString='';
	  tableData.actionQueryString='all';
	  tableData.reasonQueryString='all';
	  tableData.deviceQueryString='all';
	  tableData.directionQueryString='all';
	  tableData.resourceGroupQueryString='all';
	  tableData.categoryQeryString='all';
	  tableData.listQueryString='';
	  tableData.typeQueryString='all';
	  tableData.facilityQueryString='all';
	  tableData.priorityQueryString='all';
	  tableData.messageQueryString='';
	  tableData.query='';
	  tableData.dateRangeObj= {};
	  tableData.sourceIpObj = {};
	  tableData.dstIpObj = {};
	  tableData.timestampArr= [];
	  tableData.protocolArr= [];
	  tableData.actionArr=[];
	  tableData.reasonArr= [];
	  tableData.resourceGroupArr= [];
	  tableData.deviceArr=[];
	  tableData.countryArr=[];
	  tableData.directionArr=[];
	  tableData.categoryArr=[];
	  tableData.groupArr=[];
      tableData.rows= [];
	  tableData.type = type;
	  tableData.userArr = [];
	  tableData.moduleQueryString='all';
	  tableData.actionTypeQueryString='all';
	  tableData.userTypeQueryString='all';
	if (type === "domain") {
		esURL = esDomainURL;
	} else if (type === "packet") {
		esURL = esPacketURL;
	} else if (type === "system") {
		esURL = esSystemURL;
	} else if (type === "audit") {
		esURL = esAuditURL;
	}
	getLogs(tableData.from);
}

Vue.filter('capitalize', function (value) {
  if (!value) return ''
  value = value.toString()
  return value.charAt(0).toUpperCase() + value.slice(1)
});

var tableData = new Vue({
  el: '#root',
  data: {
	  uname: '',
	  pwd: '',
	  from:0,
	  pageSize: 20,
	  oldDocs: 'asc',
	  newDocs: 'desc',
	  dateQueryString:'',
	  domainQueryString:'',
	  protoQueryString:'all',
	  sourceQueryString:'',
	  destinationQueryString:'',
	  actionQueryString:'all',
	  reasonQueryString:'all',
	  deviceQueryString:'all',
	  countryQueryString:'all',
	  directionQueryString:'all',
	  resourceGroupQueryString:'all',
	  categoryQeryString:'all',
	  listQueryString:'',
	  typeQueryString:'all',
	  facilityQueryString:'all',
	  priorityQueryString:'all',
	  messageQueryString:'',
	  type:'',
	  query:'',
	  emailAlertArray:'',
	  emailAlertSendLog:'daily',
	  emailAlertdayOfWeek:'',
	  emailAlertTime:'',
	  emailAlertFileFormat:'csv',
	  emailAlertChecked:'',
	  emailAlertPacketCountry:'Select Country',
	  emailAlertPacketASN:'',
	  emailAlertPacketProtocol:'Select Protocol',
	  emailAlertPacketSource:'',
	  emailAlertPacketDestination:'',
	  emailAlertPacketDirection:'Select Direction',
	  emailAlertPacketAction:'Select Action',
	  emailAlertPacketCategory:'Select Category',
	  emailAlertPacketReason:'Select Reason',
	  emailAlertPacketList:'',
	  emailAlertPacketResourceGroup:'Select Resource Group',
	  emailAlertPacketDevice:'Select Device',
	  emailAlertDomainDomain:'',
	  emailAlertDomainProtocol:'Select Protocol',
	  emailAlertDomainSource:'',
	  emailAlertDomainDestination:'',
	  emailAlertDomainAction:'Select Action',
	  emailAlertDomainReason:'Select Reason',
	  emailAlertDomainDevice:'Select Device',
	  emailAlertTabName: 'packet',
	  dateRangeObj: {},
	  sourceIpObj: {},
	  dstIpObj: {},
	  fieldsArr: [],
	  typeDropdownArr: [],
	  facilityDropdownArr:[],
	  priorityDropdownArr:[],
	  reasonDropdownArr: [],
	  categoryDropdownArr: [],
	  protocolDropdownArr: [],
	  countryDropdownArr: [],
	  timestampArr: [],
	  protocolArr: [],
	  actionArr: [],
	  reasonArr: [],
	  resourceGroupArr: [],
	  deviceArr:[],
	  timezoneArr:[],
	  countryArr:[],
	  directionArr:[],
	  categoryArr:[],
	  groupArr:[],
      rows: [],
      moduleDropdownArr:[],
      auditUsernameArr:[],
      moduleQueryString:'all',
	  actionTypeQueryString:'all',
	  userTypeQueryString:'all',
	  userArr:[],
	  auditActionDropdownArr:[],
	  emailRows: [],
	  editable: false,
	  countryPolicyList:[],
	  countryList: [],
	  allCountryList:[],
	  countryCode:'',
	  sourceList: [
		{
			text: 'Whitelist',
			children: [
				{
					text: 'Group1',
				},
				{
					text: 'Group2',
				}
			]
		},
		{
			text: 'Blacklist',
			children: [
				{
					text: 'Group1',
				},
				{
					text: 'Group2',
				}
			]
		},
		
	]
  },
  //components: {dateRangePicker},
   methods: {
	   addCountryToAllowedOrDenied: function(indexList){
		var policyObj = {}
		var type = '';
		policyName = tableData.countryList[indexList[0]].text;
		for(i in tableData.countryPolicyList) {
			if(Object.values(tableData.countryPolicyList[i]).includes(policyName)){
				policyObj = tableData.countryPolicyList[i]
			}
		}
		console.log("inside test->"+policyObj+", policy uuid->"+policyObj.uuid);
		console.log("inside test->"+tableData.countryCode);
		if(indexList[0,1] == 0){
			type = "allowed";
		} else if(indexList[0,1] == 1){
			type = "denied";
		}
		countryAllowedOrDenied(policyObj.uuid, tableData.countryCode, type)
    },
	setCountryCode: function(country){
		for(i in tableData.allCountryList){
			if(Object.values(tableData.allCountryList[i]).includes(country)) {
				tableData.countryCode = tableData.allCountryList[i].code;
			}
		}
		console.log("inside setCountryCode->"+tableData.countryCode);
	},
	login: function () {
		dataToBeSent = {
					"username":tableData.uname,
					"password":tableData.pwd
				};
		$.ajax({
			url: serviceApiUrl+"/login",
			type: 'post',
			data: JSON.stringify(dataToBeSent),
			headers: {
				"Content-Type": 'application/json'
			},
			dataType: 'json',
			success: function (data) {
				window.localStorage.setItem("token", data.token);
				console.log(window.localStorage.getItem('token'));
				$('#content').removeClass('hidden');
				
			$('#login').addClass('hidden');
			$('#logout').removeClass('hidden');
			$('#lblLoginErrMsg').addClass('hidden');
			setURL("packet");
			getPolicies();
			getAllCountries();
			},
			error: function (request, status, error) {
				console.log(status);
				$('#lblLoginErrMsg').removeClass('hidden');
			}
		});
	},
	logout: function () {
			$('#content').addClass('hidden');
				$('#logout').addClass('hidden');
			$('#login').removeClass('hidden');
			$('#editEmailAlert').addClass('hidden');
			$('#emailAlert').addClass('hidden');
			window.localStorage.removeItem('token');
	},
	setEmailAlert: function (){
		resetEmailAlertData();
		$('#content').addClass('hidden');
		$('#emailAlert').removeClass('hidden');
	},
	emailAlertCancle: function (){
		resetEmailAlertData();
		$('#content').removeClass('hidden');
		$('#emailAlert').addClass('hidden');
	},
	editEmailAlertCancle: function (){
		$('#emailAlert').removeClass('hidden');
		$('#editEmailAlert').addClass('hidden');
	},
	emailAlertFieldSelectPrompt: function (actualType,type){
		if(isEmailFieldSelected(getLogObject(type))) {
			alert('Selected '+type+' filds are not saved');
		}
		resetEmailAlertData();
		tableData.emailAlertTabName = actualType;
	},
	saveEmailAlert: function (){
		if(tableData.emailAlertChecked) {
			tableData.emailAlertTabName = 'packet';
		}
		if(tableData.emailAlertTabName == 'packet' && !tableData.emailAlertTabName) {
			var packetFieldsObject = getLogObject('packet');
		} else if(tableData.emailAlertTabName == 'domain') {
			var domainFieldsObject = getLogObject('domain');
		}
		var emailArray = tableData.emailAlertArray.split(",");
		var dataObject = {
			"email": emailArray,
			"sendLog": tableData.emailAlertSendLog,
			"dayOfWeek": tableData.emailAlertdayOfWeek,
			"time": tableData.emailAlertTime,
			"fileFormat": tableData.emailAlertFileFormat,
			"includeAll": tableData.emailAlertChecked,
			"domain": domainFieldsObject,
			"packet": packetFieldsObject,
			"logType": tableData.emailAlertTabName
		};
		$.ajax({
			url: serviceApiUrl+"/emailalert",
			type: 'post',
			data: JSON.stringify(dataObject),
			headers: {
				"Content-Type": 'application/json',
				"Authorization": "Token "+window.localStorage.getItem('token')
			},
			success: function (data) {
				$.growl({
					title: "Success",
					message:"Enabled Email Alert"
				});
				$('#content').removeClass('hidden');
				$('#emailAlert').addClass('hidden');
			},
			error: function (request, status, error) {
				$.growl.warning({
					message:"Something went wrong! "+error
				});
			}
		});
	},
	editEmailAlert: function (){
		var editUrl = serviceApiUrl+"/editemailalert"
		$.ajax({
			url: editUrl,
			type: 'get',
			headers: {
				"Content-Type": 'application/json',
				"Authorization": "Token "+window.localStorage.getItem('token')
			},
			success: function (data) {
				tableData.emailRows = data;
				$('#editEmailAlert').removeClass('hidden');
				$('#emailAlert').addClass('hidden');
			},
			error: function (request, status, error) {
				$.growl.warning({
					message:"Something went wrong! "+error
				});
			}
		});
	},
	edit_page_email_alert: function (emailAlertObj) {
		$('#editEmailAlert').addClass('hidden');
		$('#emailAlert').removeClass('hidden');
		tableData.emailAlertArray = emailAlertObj.fields.email
		tableData.emailAlertSendLog = emailAlertObj.fields.send_log
		tableData.emailAlertTime = emailAlertObj.fields.time
		tableData.emailAlertFileFormat = emailAlertObj.fields.file_format
		tableData.emailAlertChecked = emailAlertObj.fields.include_all
		tableData.emailAlertdayOfWeek = emailAlertObj.fields.day_of_week
		if(emailAlertObj.fields.log_type === 'packet') {
			
		}
	},
	delete_email_alert: function (id){
		var url = serviceApiUrl+"/deleteemailalert"
		dataObject = {
			"id": id
		}
		$.ajax({
			url: url,
			type: 'delete',
			data: JSON.stringify(dataObject),
			headers: {
				"Content-Type": 'application/json',
				"Authorization": "Token "+window.localStorage.getItem('token')
			},
			success: function (data) {
				tableData.emailRows = data;
				$.growl({
					title: "Success",
					message:"Email alert deleted"
		});
			},
			error: function (request, status, error) {
				$.growl.warning({
					message:"Something went wrong! "+error
				});
			}
		});
	},
	getLogsByType: function (type) {
		setURL(type);
	},
	resetSearchFilters: function () {
		tableData.dateQueryString ='';
		tableData.domainQueryString='';
		tableData.protoQueryString='all';
		tableData.sourceQueryString='';
		tableData.destinationQueryString='';
		tableData.actionQueryString='all';
		tableData.reasonQueryString='all';
		tableData.deviceQueryString='all';
		tableData.countryQueryString='all';
		tableData.directionQueryString='all';
		tableData.resourceGroupQueryString='all';
		tableData.categoryQeryString='all';
		tableData.listQueryString='';
		tableData.typeQueryString='all',
		tableData.facilityQueryString='all',
		tableData.priorityQueryString='all',
		tableData.messageQueryString='',
		tableData.query = '';
		tableData.dateRangeObj = {};
		tableData.sourceIpObj = {};
		tableData.dstIpObj = {};
		tableData.moduleQueryString='all',
		tableData.actionTypeQueryString='all',
		tableData.userTypeQueryString='all'
		getLogs(tableData.from);
	},
	dateFilter: function (inputName) {
		$('input[name="'+inputName+'"]').daterangepicker({
			timePicker: true,
			autoUpdateInput: false,
			showDropdowns: true,
			opens: 'right',
			drops: 'down',
			ranges: {
				'Today': [moment()],
				'Yesterday': [moment().subtract(1, 'days')],
				'Last 7 Days': [moment().subtract(6, 'days'), moment()],
				'Last 30 Days': [moment().subtract(29, 'days'), moment()],
				'This Month': [moment().startOf('month'), moment().endOf('month')],
				'Last Month': [moment().subtract(1, 'month').startOf('month'), moment().subtract(1, 'month').endOf('month')]
			},
			locale: {
				cancelLabel: 'Clear',
			}
		}).focus();

		$('input[name="'+inputName+'"]').on('apply.daterangepicker', function(ev, picker) {
			//$(this).val(picker.startDate.format('MM/DD/YYYY') + ' - ' + picker.endDate.format('MM/DD/YYYY'));
			if(picker.chosenLabel === 'Today' || picker.chosenLabel === 'Yesterday') {
				tableData.dateQueryString = $(this).val(picker.startDate.format('MM/DD/YYYY'))[0].value;
			} else {
				tableData.dateQueryString = $(this).val(picker.startDate.format('MM/DD/YYYY hh:mm A')+ ' - ' + picker.endDate.format('MM/DD/YYYY hh:mm A'))[0].value;
			}
			tableData.getFromQuery(event);
		});
		$('input[name="'+inputName+'"]').on('cancel.daterangepicker', function(ev, picker) {
			$(this).val('');
			tableData.dateQueryString = '';
			tableData.getFromQuery(event);
		});
		
	},
    getFromQuery: function (event) {	
			tableData.query = '';
			tableData.fieldsArr = [];
			tableData.dateRangeObj = {};
			tableData.sourceIpObj={};
			tableData.dstIpObj={};
			if(tableData.dateQueryString) {
				dateArr = tableData.dateQueryString.split("-");
				if (dateArr.length > 1) {
					tableData.dateRangeObj = {
						"timestamp": {
							"gte": moment.utc(dateArr[0]),
							"lte": moment.utc(dateArr[1])
						}
					}
				} else if(dateArr.length == 1) {
					tableData.dateRangeObj = {
						"timestamp": {
							"gte": moment.utc(dateArr[0]).format('YYYY-MM-DD'),
							"lte": moment.utc(dateArr[0]).format('YYYY-MM-DD')
						}
					}
				}
			}
			if(tableData.typeQueryString && !tableData.typeQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.typeQueryString;
				} else {
					tableData.query = tableData.typeQueryString;
				}
				tableData.fieldsArr.push("message");
			}
			if(tableData.facilityQueryString && !tableData.facilityQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.facilityQueryString;
				} else {
					tableData.query = tableData.facilityQueryString;
				}
				tableData.fieldsArr.push("Facility");
			}
			if(tableData.priorityQueryString && !tableData.priorityQueryString.includes("all")) {
				if(tableData.priorityQueryString.includes("ERROR")) {
					if(tableData.query){
						tableData.query = tableData.query+" AND err";
					} else {
						tableData.query = "err";
					}
				}else {
					if(tableData.query){
						tableData.query = tableData.query+" AND "+tableData.priorityQueryString;
					} else {
						tableData.query = tableData.priorityQueryString;
					}
				}
				tableData.fieldsArr.push("Priority");
			}
			if(tableData.messageQueryString && !tableData.messageQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.messageQueryString;
				} else {
					tableData.query = tableData.messageQueryString;
				}
				tableData.fieldsArr.push("Message");
			}
			if(tableData.listQueryString && !tableData.listQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.listQueryString;
				} else {
					tableData.query = tableData.listQueryString;
				}
				tableData.fieldsArr.push("threatlists");
				tableData.fieldsArr.push("whitelists");
				tableData.fieldsArr.push("blacklists");
			}
			if(tableData.domainQueryString && !tableData.domainQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.domainQueryString;
				} else {
					tableData.query = tableData.domainQueryString;
				}
				if(tableData.type == "domain") {
					tableData.fieldsArr.push("Domain");
				} else if (tableData.type == "packet") {
					tableData.fieldsArr.push("asName");
				}
			}
			if(tableData.protoQueryString && !tableData.protoQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.protoQueryString;
				} else {
					tableData.query = tableData.protoQueryString;
				}
				if(tableData.type == "domain") {
					tableData.fieldsArr.push("Proto");
				} else if (tableData.type == "packet") {
					tableData.fieldsArr.push("Proto");
				}
			}
			if(tableData.sourceQueryString && !tableData.sourceQueryString.includes("all")) {
				if(tableData.type == "domain") {
					tableData.sourceIpObj = {
						 "term": {
							"Source": tableData.sourceQueryString
						}
					}
				} else if (tableData.type == "packet") {
					tableData.sourceIpObj = {
						 "term": {
							"source": tableData.sourceQueryString
						}
					}
				}
			}
			if(tableData.destinationQueryString && !tableData.destinationQueryString.includes("all")) {
				if(tableData.type == "domain") {
					tableData.dstIpObj = {
						"term":{
							"DST":tableData.destinationQueryString
						}
					}
				} else if (tableData.type == "packet") {
					tableData.dstIpObj = {
						"term": {
							"destination": tableData.destinationQueryString
						}
					}
				}
			}
			if(tableData.actionQueryString && tableData.actionQueryString !== "all") {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.actionQueryString;
				} else {
					tableData.query = tableData.actionQueryString;
				}
				if(tableData.type == "domain") {
					tableData.fieldsArr.push("Action");
				} else if (tableData.type == "packet") {
					tableData.fieldsArr.push("Action");
				}
			}
			if(tableData.reasonQueryString && !tableData.reasonQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.reasonQueryString;
				} else {
					tableData.query = tableData.reasonQueryString;
				}
				if(tableData.type == "domain") {
					tableData.fieldsArr.push("Reason");
				} else if (tableData.type == "packet") {
					tableData.fieldsArr.push("reason");
				}
			}
			if(tableData.deviceQueryString && !tableData.deviceQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.deviceQueryString;
				} else {
					tableData.query = tableData.deviceQueryString;
				}
				tableData.fieldsArr.push("HName");
			}
			if(tableData.countryQueryString && !tableData.countryQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.countryQueryString;
				} else {
					tableData.query = tableData.countryQueryString;
				}
				tableData.fieldsArr.push("Country");
			}
			if(tableData.directionQueryString && !tableData.directionQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.directionQueryString;
				} else {
					tableData.query = tableData.directionQueryString;
				}
				tableData.fieldsArr.push("Direction");
			}
			if(tableData.resourceGroupQueryString && !tableData.resourceGroupQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.resourceGroupQueryString;
				} else {
					tableData.query = tableData.resourceGroupQueryString;n
				}
				tableData.fieldsArr.push("Group");
			}
			if(tableData.categoryQeryString && !tableData.categoryQeryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.categoryQeryString;
				} else {
					tableData.query = tableData.categoryQeryString;
				}
				tableData.fieldsArr.push("matched_categories");
				tableData.fieldsArr.push("denied_categories");
			}

			if(tableData.moduleQueryString && !tableData.moduleQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.moduleQueryString;
				} else {
					tableData.query = tableData.moduleQueryString;
				}
				tableData.fieldsArr.push("moduleVal");
			}

			if(tableData.actionTypeQueryString && !tableData.actionTypeQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.actionTypeQueryString;
				} else {
					tableData.query = tableData.actionTypeQueryString;
				}
				tableData.fieldsArr.push("actionVal");
			}

			if(tableData.userTypeQueryString && !tableData.userTypeQueryString.includes("all")) {
				if(tableData.query){
					tableData.query = tableData.query+" AND "+tableData.userTypeQueryString;
				} else {
					tableData.query = tableData.userTypeQueryString;
				}
				tableData.fieldsArr.push("userVal");
			}
			/*tableData.query = tableData.dateQueryString+" "+tableData.domainQueryString+" "+tableData.protoQueryString+" "+tableData.sourceQueryString+" "+tableData.destinationQueryString+" "+tableData.actionQueryString+" "+tableData.reasonQueryString+" "+tableData.deviceQueryString;*/
			//tableData.query = tableData.query.replace(/ /g,"")
			if(tableData.query || tableData.dateQueryString || tableData.sourceQueryString || tableData.destinationQueryString) {
				queryFilter(tableData.query, tableData.pageSize);
			} else{
				tableData.getRrecentOrOldDocs('desc');
				/*$.getJSON(esURL+"?from="+tableData.from+"&size="+tableData.pageSize+"&pretty=true").then(result => {
					tableData.rows = result.hits.hits;
					for(var i=0; i<tableData.rows.length; i++) {
						var timestamp = getTimeStamp(tableData.rows[i]._source.timestamp, "UTC");
						tableData.rows[i]._source.timestamp = timestamp;
					}
					removeSpecialChars(tableData.rows);
					applyNodata();
				}, error => {
					console.log(error);
				});*/
			}
    },
	getRrecentOrOldDocs: function (sortType) {
		var dataToBeSent = {};
		var queryObj = setDataObject(tableData.query);
		if(sortType === "asc") {
			if(tableData.query || tableData.dateQueryString || tableData.sourceQueryString 
				|| tableData.destinationQueryString) {
				dataToBeSent = {
					"query": queryObj.query,
					"sort": [{
						"timestamp": {
							"order": "asc"
						}
					}]
				};
			} else {
				dataToBeSent = {
					"sort": [{
						"timestamp": {
							"order": "asc"
						}
					}]
				};
			}
			
		} else if(sortType === "desc") {
			if(tableData.query || tableData.dateQueryString || tableData.sourceQueryString 
				|| tableData.destinationQueryString) {
				dataToBeSent = {
					"query": queryObj.query,
					"sort": [{
						"timestamp": {
							"order": "desc"
						}
					}]
				};
			} else {
				dataToBeSent = {
					"sort": [{
						"timestamp": {
							"order": "desc"
						}
					}]
				};
			}
		}

		var url = esURL+"?size="+tableData.pageSize+"&pretty=true";
		$.ajax({
			url: url,
			type: 'post',
			data: JSON.stringify(dataToBeSent),
			headers: {
				"Content-Type": 'application/json'
			},
			dataType: 'json',
			success: function (data) {
				tableData.rows = data.hits.hits;
				/*for(var i=0; i<tableData.rows.length; i++) {
					var timestamp = getTimeStamp(tableData.rows[i]._source.timestamp, "UTC");
					tableData.rows[i]._source.timestamp = timestamp;
				}*/
				removeSpecialChars(tableData.rows)
				applyNodata();
				setDataArrays(tableData.rows);
			}
		});
	},
	nextPage: function () {
		tableData.from = tableData.pageSize+tableData.from;
		getLogs(tableData.from);
	},
	previousPage: function () {
		if(tableData.from >= tableData.pageSize){
			tableData.from = tableData.from-tableData.pageSize;
		}
		getLogs(tableData.from);
	},
	setPageSize: function (event) {
		if(tableData.query || tableData.dateQueryString || tableData.sourceQueryString 
				|| tableData.destinationQueryString) {
			queryFilter(tableData.query, tableData.pageSize)
		} else {
			getLogs(tableData.from);
		}
	},
	setTimezone: function (event) {
		for(var i=0; i<tableData.rows.length; i++) {
			var timestamp = getTimeStamp(tableData.timestampArr[i], event.target.value);
			tableData.rows[i]._source.timestamp = timestamp;
		}
	},
	copyToClipboard () {
		if (tableData.rows.length <= 0) {
			displayGrowlMessage();
			return;
		}
		var obj = []
		var range = document.createElement("textarea");
		document.body.appendChild(range);
		if (tableData.type === 'packet') {
			for (var row in tableData.rows) {
				var rowObj = {
					"timestamp":tableData.rows[row]._source.timestamp,
					"country":tableData.rows[row]._source.Country,
					"asName":tableData.rows[row]._source.asName,
					"proto":tableData.rows[row]._source.Proto,
					"source":tableData.rows[row]._source.source+":"+tableData.rows[row]._source.sourcePort,
					"destination":tableData.rows[row]._source.destination+":"+tableData.rows[row]._source.destinationPort,
					"direction":tableData.rows[row]._source.Direction,
					"action":tableData.rows[row]._source.Action,
					"category":tableData.rows[row]._source.category,
					"reason":tableData.rows[row]._source.reason,
					"threatlist":tableData.rows[row]._source.threatlists,
					"whitelist":tableData.rows[row]._source.whitelists,
					"blacklist":tableData.rows[row]._source.blacklists,
					"group":tableData.rows[row]._source.Group,
					"hostName":tableData.rows[row]._source.HName
				}
				obj.push(rowObj);
			}
		} else if (tableData.type === 'domain') {
			for (var row in tableData.rows) {
				var rowObj = {
					"timestamp":tableData.rows[row]._source.timestamp,
					"domain":tableData.rows[row]._source.Domain,
					"proto":tableData.rows[row]._source.Proto,
					"source":tableData.rows[row]._source.Source,
					"destination":tableData.rows[row]._source.DST,
					"action":tableData.rows[row]._source.Action,
					"reason":tableData.rows[row]._source.Reason,
					"hostName":tableData.rows[row]._source.HName
				}
				obj.push(rowObj);
			}
		} else if (tableData.type === 'system') {
			for (var row in tableData.rows) {
				var rowObj = {
					"timestamp":tableData.rows[row]._source.timestamp,
					"type":"",
					"facility":tableData.rows[row]._source.Facility,
					"priority":tableData.rows[row]._source.Priority,
					"message":tableData.rows[row]._source.Message,
					"hostName":tableData.rows[row]._source.HName
				}
				obj.push(rowObj);
			}
		} else if (tableData.type === 'audit') {
			for (var row in tableData.rows) {
				var rowObj = {
					"timestamp":tableData.rows[row]._source.timestamp,
					"Module":tableData.rows[row]._source.moduleVal,
					"Action":tableData.rows[row]._source.actionVal,
					"User":tableData.rows[row]._source.userVal,
					"HName":tableData.rows[row]._source.HName,
					"Message":tableData.rows[row]._source.message
				}
				obj.push(rowObj);
			}
		}
		range.value = getCsvObject(obj);
		range.select();
		//var el = {};
		/*if (tableData.type === 'packet') {
			el = this.$refs.packetTable;
		} else if (tableData.type === 'domain') {
			el = this.$refs.domainTable;
		} else if (tableData.type === 'system') {
			el = this.$refs.systemTable;
		}
		  var body = document.body, range, sel;
			if (document.createRange && window.getSelection) {
				range = document.createRange();
				sel = window.getSelection();
				sel.removeAllRanges();
				try {
					range.selectNodeContents(el);
					sel.addRange(range);
				} catch (e) {
					range.selectNode(el);
					sel.addRange(range);
				}
			} else if (body.createTextRange) {
				range = body.createTextRange();
				range.moveToElementText(el);
				range.select();
			}*/
			document.execCommand("Copy");
			document.body.removeChild(range);
			displayGrowlMessage();
			
			window.getSelection().removeAllRanges();
        }
  }
     
});

var displayGrowlMessage = function () {
	if(tableData.rows.length > 0){
		$.growl({
			title: "Success",
				message:tableData.rows.length+" lines copied to clipboard"
		});
	} else if(tableData.rows.length == 0) {
		$.growl.warning({message: "There is no data to select!"});
	}
}

var applyNodata = function () {
	if(tableData.rows.length == 0) {
		$('#noData').removeClass('hidden');
	}else {
		$('#noData').addClass('hidden');
	}
}

var validateQueryStrings = function () {
	var queryValidation = false;
	if(!tableData.dateQueryString && !tableData.domainQueryString && (!tableData.protoQueryString || tableData.protoQueryString === 'all') && 
		!tableData.sourceQueryString && !tableData.destinationQueryString && (!tableData.actionQueryString || tableData.actionQueryString === 'all') && (!tableData.reasonQueryString || tableData.reasonQueryString === 'all') && (!tableData.deviceQueryString || tableData.deviceQueryString === 'all') && !tableData.countryQueryString) {
			queryValidation = false;
	} else { queryValidation = true;}
	return queryValidation;
}

var getLogs = function(from) {
	if(tableData.query.length > 0 || tableData.dateQueryString || tableData.sourceQueryString 
		|| tableData.destinationQueryString){
		var url = "";
	if(from > 0) {
		url = esURL+"?from="+from+"&size="+tableData.pageSize+"&pretty=true";
	} else {
		url = esURL+"?size="+tableData.pageSize+"&pretty=true";
	}
	var url = esURL+"?from="+tableData.from+"&size="+tableData.pageSize+"&pretty=true";
	var dataToBeSent = setDataObject(tableData.query);
	$.ajax({
			url: url,
			type: 'post',
			data: JSON.stringify(dataToBeSent),
			headers: {
				"Content-Type": 'application/json'
			},
			dataType: 'json',
			success: function (data) {
				tableData.rows = data.hits.hits;
				applyNodata();
				setDataArrays(tableData.rows);
				/*for(var i=0; i<tableData.rows.length; i++) {
					var timestamp = getTimeStamp(tableData.rows[i]._source.timestamp, "UTC");
					tableData.rows[i]._source.timestamp = timestamp;
				}*/
				removeSpecialChars(tableData.rows)
			}
		});
	} else {
		if(from > 0) {
		$.getJSON(esURL+"?from="+from+"&size="+tableData.pageSize+"&pretty=true").then(result => {
			tableData.rows = result.hits.hits;
			applyNodata();
			setDataArrays(tableData.rows);
		}, error => {
			console.log(error);
		});
		} else {
			tableData.getRrecentOrOldDocs('desc');
			/*$.getJSON(esURL+"?size="+tableData.pageSize+"&pretty=true").then(result => {
			tableData.rows = result.hits.hits;
			applyNodata();
			setDataArrays(tableData.rows);
		}, error => {
			console.log(error);
		});*/
	}
	}
	
	
}

var setDataArrays = function(dataRows) {
	for (var i=0; i<dataRows.length; i++) {
		tableData.timestampArr.push(dataRows[i]._source.timestamp);
		var timestamp = getTimeStamp(dataRows[i]._source.timestamp, "UTC");
		tableData.rows[i]._source.timestamp = timestamp;
		if(dataRows[i]._source.Country){
			var country = dataRows[i]._source.Country.replace(/"/g, "");
			tableData.rows[i]._source.Country = country;
			if(!tableData.countryArr.includes(country)) {
				tableData.countryArr.push(country);
			}
		}
	}
	$.getJSON(esURL+"?size=10000&pretty=true").then(result => {
			data = result.hits.hits;
		for(var i=0; i<data.length; i++) {
		if(!tableData.protocolArr.includes(data[i]._source.Proto)) {
			tableData.protocolArr.push(data[i]._source.Proto);
		}
		if(!tableData.actionArr.includes(data[i]._source.Action)){
			tableData.actionArr.push(data[i]._source.Action);
		}
		if(data[i]._source.reason) {
			if(!tableData.reasonArr.includes(data[i]._source.reason)){
			tableData.reasonArr.push(data[i]._source.reason);
			}
		}
		if(data[i]._source.Reason) {
			if(!tableData.reasonArr.includes(data[i]._source.Reason)){
				tableData.reasonArr.push(data[i]._source.Reason);
			}
		}
		if(data[i]._source.Group) {
			var group = data[i]._source.Group.replace(/"/g, "")
			tableData.rows[i]._source.Group = group;
			if(!tableData.groupArr.includes(group)){
				tableData.groupArr.push(group);
			}
		}
		if(!tableData.resourceGroupArr.includes(data[i]._source.Direction)){
			tableData.resourceGroupArr.push(data[i]._source.Direction);
		}
		if(!tableData.deviceArr.includes(data[i]._source.HName)){
			tableData.deviceArr.push(data[i]._source.HName);
		}
		if(!tableData.userArr.includes(data[i]._source.userVal)){
			tableData.userArr.push(data[i]._source.userVal);
		}
		// if(!tableData.auditActionDropdownArr.includes(data[i]._source.actionVal)){
		// 	tableData.auditActionDropdownArr.push(data[i]._source.actionVal);
		// }
		if(!tableData.directionArr.includes(data[i]._source.Direction)) {
			tableData.directionArr.push(data[i]._source.Direction);
		}
		}
		}, error => {
			console.log(error);
		});
	removeSpecialChars(dataRows);
}

var removeSpecialChars = function(data) {
	for(var i=0;i<data.length;i++){
		if(data[i]._source.asName) {
			tableData.rows[i]._source.asName = data[i]._source.asName.replace(/"/g, "");
		}
		if(data[i]._source.destinationPort && data[i]._source.destinationPort.includes(",")) {
			tableData.rows[i]._source.destinationPort = data[i]._source.destinationPort.substr(0, data[i]._source.destinationPort.indexOf(','));
		}
		if(data[i]._source.Country){
			tableData.rows[i]._source.Country = data[i]._source.Country.replace(/"/g, "");
		}
		if(data[i]._source.Group) {
			tableData.rows[i]._source.Group = data[i]._source.Group.replace(/"/g, "")
		}
	}
}

//$(document).ready(function () {
  //$('#logTable').DataTable({
   // "pagingType": "full" // 'First', 'Previous', 'Next' and 'Last' buttons
  //});
  //$('.dataTables_length').addClass('bs-select');
//});

var queryFilter = function(queryString) {
	var url = esURL+"?from="+tableData.from+"&size="+tableData.pageSize;
	var dataToBeSent = {};
	var queryObj = setDataObject(queryString);
	dataToBeSent = {
		"query": queryObj.query,
		"sort": [{
			"timestamp": {
				"order": "desc"
			}
		}]
	};

	$.ajax({
			url: url,
			type: 'post',
			data: JSON.stringify(dataToBeSent),
			headers: {
				"Content-Type": 'application/json'
			},
			dataType: 'json',
			success: function (data) {
				tableData.rows = data.hits.hits;
				applyNodata();
				for(var i=0; i<tableData.rows.length; i++) {
					var timestamp = getTimeStamp(tableData.rows[i]._source.timestamp, "UTC");
					tableData.rows[i]._source.timestamp = timestamp;
				}
				removeSpecialChars(tableData.rows)
			}
		});
}

var getTimeStamp = function(timestamp, timezone) {
	var date = new Date(timestamp);
		 return date.toLocaleString("en-US", {timeZone: timezone});
}

$(function () {
	$('#datetimepicker').datetimepicker();
});

var getCsvObject = function(obj) {
	const items = obj;
	const replacer = (key, value) => value === null ? '' : value // specify how you want to handle null values here
	const header = Object.keys(items[0])
	let csv = items.map(row => header.map(fieldName => JSON.stringify(row[fieldName], replacer)).join(','))
	csv.unshift(header.join(','))
	csv = csv.join('\r\n')
	return csv;
	console.log(csv)
}

var setDataObject = function (queryString) {
	var dataToBeSent = {
		"query":{
			"bool":{
				"must":[]
			}
		}
	};
	if (tableData.dateQueryString || tableData.sourceQueryString || tableData.destinationQueryString) {
		var rangeObj = {
			"range": tableData.dateRangeObj
		}
		if(!tableData.query){
			if(tableData.dateQueryString) {
				dataToBeSent.query.bool.must.push(rangeObj);
			}
			if(tableData.sourceQueryString) {
				dataToBeSent.query.bool.must.push(tableData.sourceIpObj);
			}
			if(tableData.destinationQueryString) {
				dataToBeSent.query.bool.must.push(tableData.dstIpObj);
			}
		} else {
			var queryStringObj = {
					"query_string" : {
						"fields" : tableData.fieldsArr,
						"query" : queryString
					}
				}
			dataToBeSent.query.bool.must.push(queryStringObj);
			if(tableData.dateQueryString) {
				dataToBeSent.query.bool.must.push(rangeObj);
			}
			if(tableData.sourceQueryString) {
				dataToBeSent.query.bool.must.push(tableData.sourceIpObj);
			}
			if(tableData.destinationQueryString) {
				dataToBeSent.query.bool.must.push(tableData.dstIpObj);
			}
		}
	} else {
		var queryStringObj = {
					"query_string" : {
						"fields" : tableData.fieldsArr,
						"query" : queryString
					}
				}
	   dataToBeSent.query.bool.must.push(queryStringObj);
			
	} //else close
	return dataToBeSent;
}
var getLogObject = function (type) {
	if(type === 'packet'){
		var packetObj = {
					"country":tableData.emailAlertPacketCountry,
					"asName":tableData.emailAlertPacketASN,
					"proto":tableData.emailAlertPacketProtocol,
					"source":tableData.emailAlertPacketSource,
					"destination":tableData.emailAlertPacketDestination,
					"direction":tableData.emailAlertPacketDirection,
					"action":tableData.emailAlertPacketAction,
					"category":tableData.emailAlertPacketCategory,
					"reason":tableData.emailAlertPacketReason,
					"list":tableData.emailAlertPacketList,
					"group":tableData.emailAlertPacketResourceGroup,
					"hostName":tableData.emailAlertPacketDevice
				}
		return packetObj;
	}
	if(type === 'domain'){
		var domainObj = {
					"domain":tableData.emailAlertDomainDomain,
					"proto":tableData.emailAlertDomainProtocol,
					"source":tableData.emailAlertDomainSource,
					"destination":tableData.emailAlertDomainDestination,
					"action":tableData.emailAlertDomainAction,
					"reason":tableData.emailAlertDomainReason,
					"hostName": tableData.emailAlertDomainDevice
				}
		return domainObj;
	}
}

var isEmailFieldSelected = function (obj) {
	var valueArray = Object.values(obj);
	for (var index in valueArray){
		if(!valueArray[index].includes('Select') && valueArray[index]) {
			return true;
		}
	}
	return false;
}

var resetEmailAlertData = function () {
	  tableData.emailAlertArray='';
	  tableData.emailAlertSendLog='daily';
	  tableData.emailAlertdayOfWeek='';
	  tableData.emailAlertTime='';
	  tableData.emailAlertFileFormat='csv';
	  tableData.emailAlertChecked='';
	  tableData.emailAlertPacketCountry='Select Country';
	  tableData.emailAlertPacketASN='';
	  tableData.emailAlertPacketProtocol='Select Protocol';
	  tableData.emailAlertPacketSource='';
	  tableData.emailAlertPacketDestination='';
	  tableData.emailAlertPacketDirection='Select Direction';
	  tableData.emailAlertPacketAction='Select Action';
	  tableData.emailAlertPacketCategory='Select Category';
	  tableData.emailAlertPacketReason='Select Reason';
	  tableData.emailAlertPacketList='';
	  tableData.emailAlertPacketResourceGroup='Select Resource Group';
	  tableData.emailAlertPacketDevice='Select Device';
	  tableData.emailAlertDomainDomain='';
	  tableData.emailAlertDomainProtocol='Select Protocol';
	  tableData.emailAlertDomainSource='';
	  tableData.emailAlertDomainDestination='';
	  tableData.emailAlertDomainAction='Select Action';
	  tableData.emailAlertDomainReason='Select Reason';
	  tableData.emailAlertDomainDevice='Select Device';
	  tableData.emailAlertTabName = 'packet';
}

var getPolicies = function () {
	dataToBeSent = {
		"policy": "policy"
	}
	internalServiceGetData(dataToBeSent);
}

var getAllCountries = function () {
	dataToBeSent = {
		"country": "country"
	}
	internalServiceGetData(dataToBeSent);
}

var internalServiceGetData = function (dataToBeSent) {
	$.ajax({
			url: serviceApiUrl+"/getfromgmc",
			type: 'post',
			data: JSON.stringify(dataToBeSent),
			headers: {
				"Content-Type": 'application/json',
				"Authorization": "Token "+window.localStorage.getItem('token')
			},
			dataType: 'json',
			success: function (data) {
				console.log('policy data-> '+data);
				if(dataToBeSent.hasOwnProperty('policy')){
					tableData.countryPolicyList = data;
					for(var i in tableData.countryPolicyList) {
						countryListObj = {
							text: tableData.countryPolicyList[i].name,
							children: [
								{
									text: 'Allow',
								},
								{
									text: 'Deny'
								}
							]
						}
						tableData.countryList.push(countryListObj)
					}
					console.log('country policy list->'+tableData.countryList)
				}
				if(dataToBeSent.hasOwnProperty('country')) {
					tableData.allCountryList = data;
				}

			},
			error: function (request, status, error) {
				console.log(status);
			}
		});
}

var countryAllowedOrDenied = function (policyId, countryCode, type) {
	dataToBeSent = {
		"policy_uuid": policyId,
		"country_code": countryCode,
		"type": type
	}
	$.ajax({
			url: serviceApiUrl+"/countryallowordeny",
			type: 'post',
			data: JSON.stringify(dataToBeSent),
			headers: {
				"Content-Type": 'application/json',
				"Authorization": "Token "+window.localStorage.getItem('token')
			},
			dataType: 'json',
			success: function (data) {
				console.log('policy data-> '+data);
				$.growl({
					title: "Success",
					message:"Country added to "+type
				});
			},
			error: function (request, status, error) {
				console.log(status);
			}
		});
}

/*$('input[name="daterange"]').daterangepicker({
        startDate: moment(),
        endDate: moment(),
		showCustomRangeLabel: true,
        ranges: {
           'Today': [moment(), moment()],
           'Yesterday': [moment().subtract(1, 'days'), moment().subtract(1, 'days')],
           'Last 7 Days': [moment().subtract(6, 'days'), moment()],
           'Last 30 Days': [moment().subtract(29, 'days'), moment()],
           'This Month': [moment().startOf('month'), moment().endOf('month')],
           'Last Month': [moment().subtract(1, 'month').startOf('month'), moment().subtract(1, 'month').endOf('month')]
        }
    });*/
	
	

$(function() {

  $('input[name="daterange"]').daterangepicker({
      autoUpdateInput: false,
	  singleDatePicker: true,
	  ranges: {
           'Today': [moment(), moment()],
           'Yesterday': [moment().subtract(1, 'days'), moment().subtract(1, 'days')],
           'Last 7 Days': [moment().subtract(6, 'days'), moment()],
           'Last 30 Days': [moment().subtract(29, 'days'), moment()],
           'This Month': [moment().startOf('month'), moment().endOf('month')],
           'Last Month': [moment().subtract(1, 'month').startOf('month'), moment().subtract(1, 'month').endOf('month')]
        },
      locale: {
          cancelLabel: 'Clear'
      }
  });

  $('input[name="daterange"]').on('apply.daterangepicker', function(ev, picker) {
      $(this).val(picker.startDate.format('MM/DD/YYYY') + ' - ' + picker.endDate.format('MM/DD/YYYY'));
	});
	$('input[name="daterange"]').on('cancel.daterangepicker', function(ev, picker) {
      $(this).val('');
  });

});


tableData.timezoneArr = ["America/Adak", "America/Anchorage","America/Anguilla","America/Aruba","America/Atikokan","America/Barbados","America/Belize","America/Blanc-Sablon","America/Boise","America/Cambridge_Bay","America/Cancun","America/Cayenne","America/Cayman","America/Chicago","America/Chihuahua","America/Costa_Rica","America/Creston","America/Danmarkshavn","America/Dawson","America/Dawson_Creek","America/Denver","America/Detroit","America/Edmonton","America/Fort_Nelson","America/Glace_Bay","America/Godthab","America/Goose_Bay","America/Grenada","America/Guadeloupe","America/Guatemala","America/Guyana","America/Halifax"," America/Hermosillo","America/Indiana/Indianapolis","America/Indiana/Knox","America/Indiana/Marengo","America/Indiana/Petersburg","America/Indiana/Tell_City"," America/Indiana/Vevay","America/Indiana/Vincennes","America/Indiana/Winamac","America/Inuvik","America/Iqaluit","America/Jamaica","America/Juneau"," America/Kentucky/Louisville"," America/Kentucky/Monticello","America/Los_Angeles","America/Lower_Princes","America/Matamoros","America/Mazatlan"," America/Menominee"," America/Merida"," America/Metlakatla"," America/Mexico_City"," America/Moncton"," America/Monterrey"," America/Montevideo"," America/Nassau","America/New_York"," America/Nipigon"," America/Nome","America/North_Dakota/Beulah","America/North_Dakota/Center","America/North_Dakota/New_Salem","America/Ojinaga","America/Panama"," America/Pangnirtung","America/Phoenix","America/Port-au-Prince","America/Puerto_Rico","America/Rainy_River","America/Rankin_Inlet","America/Regina","America/Resolute","America/Scoresbysund","America/Sitka","America/St_Johns"," America/St_Thomas","America/Swift_Current","America/Tegucigalpa","America/Thule","America/Thunder_Bay","America/Tijuana","America/Toronto","America/Vancouver","America/Whitehorse","America/Winnipeg","America/Yakutat","America/Yellowknife","Atlantic/Bermuda","Atlantic/Cape_Verde","Atlantic/Faroe","Atlantic/Reykjavik","Atlantic/Stanley","Australia/Adelaide","Australia/Brisbane","Australia/Broken_Hill","Australia/Currie","Australia/Darwin","Australia/Eucla","Australia/Hobart","Australia/Lindeman","Australia/Lord_Howe","Australia/Melbourne","Australia/Perth","Australia/Sydney","Europe/Amsterdam","Europe/Andorra","Europe/Astrakhan","Europe/Athens","Europe/Belgrade","Europe/Berlin","Europe/Bratislava","Europe/Brussels","Europe/Bucharest","Europe/Budapest","Europe/Busingen","Europe/Chisinau","Europe/Copenhagen","Europe/Dublin","Europe/Gibraltar","Europe/Guernsey","Europe/Helsinki","Europe/Isle_of_Man","Europe/Istanbul","Europe/Jersey","Europe/Kaliningrad","Europe/Kiev","Europe/Kirov","Europe/Lisbon","Europe/Ljubljana","Europe/London","Europe/Luxembourg","Europe/Madrid","Europe/Malta","Europe/Mariehamn","Europe/Minsk","Europe/Monaco","Europe/Moscow","Europe/Oslo","Europe/Paris","Europe/Podgorica","Europe/Prague","Europe/Riga","Europe/Rome","Europe/Samara","Europe/San_Marino","Europe/Saratov","Europe/Simferopol","Europe/Skopje","Europe/Sofia","Europe/Stockholm","Europe/Tallinn","Europe/Tirane","Europe/Ulyanovsk","Europe/Uzhgorod","Europe/Vaduz","Europe/Vatican","Europe/Vienna","Europe/Vilnius","Europe/Volgograd","Europe/Warsaw","Europe/Zagreb","Europe/Zaporozhye","Europe/Zurich","Indian/Antananarivo","Indian/Christmas","Indian/Cocos","Indian/Comoro","Indian/Kerguelen","Indian/Mahe","Indian/Maldives","Indian/Mauritius","Indian/Mayotte","Indian/Reunion","Pacific/Easter","Pacific/Fiji","Pacific/Gambier","Pacific/Guam","Pacific/Honolulu","Pacific/Marquesas","Pacific/Midway","Pacific/Pago_Pago","Pacific/Tahiti","Pacific/Wake","UTC"];

tableData.countryDropdownArr = ["AFGHANISTAN","ALAND ISLANDS","ALBANIA","ALGERIA","AMERICAN SAMOA","ANDORRA","ANGOLA","ANGUILLA","ANTARCTICA","ANTIGUA AND BARBUDA","ARGENTINA","ARMENIA","ARUBA","ASCENSION ISLAND","AUSTRALIA","AUSTRIA","AZERBAIJAN","BAHAMAS","BAHRAIN","BANGLADESH","BARBADOS","BELARUS","BELGIUM","BELIZE","BENIN","BERMUDA","BHUTAN","BOLIVIA","BONAIRE"," SINT EUSTATIUS AND SABA","BOSNIA AND HERZEGOWINA","BOTSWANA","BOUVET ISLAND","BRAZIL","BRITISH INDIAN OCEAN TERRITORY","BRUNEI DARUSSALAM","BULGARIA","BURKINA FASO","BURUNDI","CAMBODIA","CAMEROON","CANADA","CAPE VERDE","CAYMAN ISLANDS","CENTRAL AFRICAN REPUBLIC","CHAD","CHILE","CHINA","CHRISTMAS ISLANDS","COCOS ISLANDS","COLOMBIA","CONGO","CONGO"," DEMOCRATIC REPUBLIC OF THE","COOK ISLANDS","COSTA RICA","COTE D'IVOIRE","CROATIA (local name Hrvatska)","CUBA","CYPRUS","CZECH REPUBLIC","Comoros","Curacao","DENMARK","DJIBOUTI","DOMINICA","DOMINICAN REPUBLIC","ECUADOR","EGYPT","EL SALVADOR","EQUATORIAL GUINEA","ERITREA","ESTONIA","ETHIOPIA","European Union","FALKLAND ISLANDS","FAROE ISLANDS","FIJI","FINLAND","FRANCE","FRENCH GUIANA","FRENCH POLYNESIA","FRENCH SOUTHERN TERRITORIES","GABON","GAMBIA","GEORGIA","GERMANY","GHANA","GIBRALTAR","GREECE","GREENLAND","GRENADA","GUADELOUPE","GUAM","GUATEMALA","GUERNSEY","GUINEA","GUINEA-BISSAU","GUYANA","HAITI","HEARD ISLAND AND MCDONALD ISLANDS","HOLY SEE (VATICAN CITY STATE)","HONDURAS","HONGONG","HUNGARY","ICELAND","INDIA","INDONESIA","IRAN (ISLAMIC REPUBLIC OF)","IRAQ","IRELAND","ISLE OF MAN","ISRAEL","ITALY","JAMAICA","JAPAN","JERSEY","JORDAN","KAZAKHSTAN","KENYA","KIRIBATI","KOREA REPUBLIC OF","KOSOVO","KUWAIT","KYRGYZSTAN","LAO PEOPLE'S DEMOCRATIC REPUBLIC","LATVIA","LEBANON","LESOTHO","LIBERIA","LIBYAN ARAB JAMAHIRIYA","LIECHTENSTEIN","LITHUANIA","LUXEMBOURG","MACAU","MACEDONIA THE FORMER YUGOSLAV REPUBLIC OF","MADAGASCAR","MALAWI","MALAYSIA","MALDIVES","MALI","MALTA","MARSHALL ISLANDS","MARTINIQUE","MAURITANIA","MAURITIUS","MAYOTTE","MEXICO","MICRONESIA"," FEDERATED STATES OF","MOLDOVA REPUBLIC OF","MONACO","MONGOLIA","MONTENEGRO","MONTSERRAT","MOROCCO","MOZAMBIQUE","MYANMAR","NAMIBIA","NAURU","NEPAL","NETHERLANDS","NETHERLANDS ANTILLES","NEW CALEDONIA","NEW ZEALAND","NICARAGUA","NIGER","NIGERIA","NIUE","NON-SPEC ASIA PAS LOCATION","NORFOLK ISLAND","NORTH KOREA","NORTHERN MARIANA ISLANDS","NORWAY","OMAN","PAKISTAN","PALAU","PALESTINIAN TERRITORY OCCUPIED","PANAMA","PAPUA NEW GUINEA","PARAGUAY","PERU","PHILIPPINES","PITCAIRN","POLAND","PORTUGAL","PUERTO RICO","QATAR","RESERVED","REUNION","ROMANIA","RUSSIAN FEDERATION","RWANDA","SAINT HELENA","SAINT KITTS AND NEVIS","SAINT LUCIA","SAINT MARTIN","SAINT VINCENT AND THE GRENADINES","SAMOA","SAN MARINO","SAUDI ARABIA","SENEGAL","SERBIA","SERBIA AND MONTENEGRO","SEYCHELLES","SIERRA LEONE","SINGAPORE","SINT MAARTEN","SLOVAKIA (Slovak Republic)","SLOVENIA","SOLOMON ISLANDS","SOMALIA","SOUTH AFRICA","SOUTH GEORGIA AND SOUTH SANDWICH ISLANDS","SOUTH SUDAN","SPAIN","SRI LANKA","SUDAN","SURINAME","SVALBARD AND JAN MAYEN","SWAZILAND","SWEDEN","SWITZERLAND","SYRIAN ARAB REPUBLIC","Saint Barthelemy","Saint Pierre and Miquelon","Sao Tome and Principe","Serbia and Montenegro (Formally Yugoslavia)","TAIWAN PROVINCE OF CHINA","TAJIKISTAN","TANZANIA UNITED REPUBLIC OF","THAILAND","TOGO","TOKELAU","TONGA","TRINIDAD AND TOBAGO","TUNISIA","TURKEY","TURKMENISTAN","TURKS AND CAICOS ISLANDS","TUVALU","Timor-Leste","UGANDA","UKRAINE","UNITED ARAB EMIRATES","UNITED KINGDOM","UNITED STATES","UNITED STATES MINOR OUTLYING ISLANDS","URUGUAY","UZBEKISTAN","Unassigned","Unknown","VANUATU","VENEZUELA","VIET NAM","VIRGIN ISLANDS (BRITISH)","VIRGIN ISLANDS (U.S.)","WESTERN SAHARA","Wallis and Futuna","YEMEN","ZAMBIA","ZIMBABWE"];

tableData.protocolDropdownArr = ["ICMP","IGMP","GGP","4","ST","TCP","CBT","EGP","IGP","BBN-RCC-MON","NVP-II","PUP","ARGUS","EMCON","XNET","CHAOS","UDP","MUX","DCN-MEAS","HMP","PRM","XNS-IDP","TRUNK-1","TRUNK-2","LEAF-1","LEAF-2","RDP","IRTP","ISO-TP4","NETBLT","MFE-NSP","MERIT-INP","SEP","3PC","IDPR","XTP","DDP","IDPR-CMTP","39","IL","IPv6","SDRP","IPv6-Route","IPv6-Frag","IDRP","RSVP","GRE","MHRP","BNA","ESP","AH","I-NLSP","SWIPE","NARP","5MOBILE","TLSP","SKIP","IPv6-ICMP","IPv6-NoNxt","IPv6-Opts","61","CFTP","63","SAT-EXPAK","5KRYPTOLAN","6RVD","IPPC","68","SAT-MON","VISA","IPCV","CPNX","CPHB","WSN","PVP","BR-SAT-MON","SUN-ND","WB-MON","WB-EXPAK","ISO-IP","VMTP","SECURE-VMTP","VINES","TTP","5NSFNET-IGP","DGP","TCF","EIGRP","OSPFIGP","Sprite-RPC","LARP","MTP","AX.25","IPIP","5MICP","SCC-SP","ETHERIP","ENCAP","any","GMTP","IFMP","PNNI","PIM","ARIS","SCPS","QNX","A/N","IPComp","SNP","Compaq-Peer","IPX-in-IP","VRRP","PGM","114","L2TP","DDX","IATP","STP","SRP","UTI","SMP","SM","PTP","","FIRE","CRTP","CRUDP","SSCOPMCE","IPLT","SPS","PIPE","SCTP","FC","RSVP-E2E-IGNORE","135","136","137","138","139","140","141","142","143","144","145","146","147","148","149","150","151","152","153","154","155","156","157","158","159","160","161","162","163","164","165","166","167","168","169","170","171","172","173","174","175","176","177","178","179","180","181","182","183","184","185","186","187","188","189","190","191","192","193","194","195","196","197","198","199","200","201","202","203","204","205","206","207","208","209","210","211","212","213","214","215","216","217","218","219","220","221","222","223","224","225","226","227","228","229","230","231","232","233","234","235","236","237","238","239","240","241","242","243","244","245","246","247","248","249","250","251","252","253","254","RAW"];

tableData.categoryDropdownArr = ["Command and Control","Botnet","Spam","Scanner","Endpoint_Exploit","Web_Exploit","Drop_Site","Proxy / VPN","DDOS","Compromised","Fraudulent_Activity","Illegal_Activity","Undesirable_Activity","PP_Node","Online_Gaming","Remote_Access_Server","TOR / Anonymizer"];

tableData.reasonDropdownArr = ["POLICY","COUNTRY","ASN","BLACKLIST","WHITELIST","THREATLIST","FLOW"];

tableData.typeDropdownArr = ["SUPPRESSED","KERNEL","SYSTEM","CMD","FSM","ENG","FSMG","APACHE_ACCESS","APACHE_ERROR"];

tableData.facilityDropdownArr = ["KERNEL","USER","MAIL","DAEMON","AUTH","SYSLOG","LPR","NEWS","UUCP","CRON","AUTHPRIV","FTP"];

tableData.priorityDropdownArr = ["EMERGENCY","ALERT","CRITICAL","ERROR","WARNING","NOTICE","INFO","DEBUG"];

tableData.moduleDropdownArr = ["ALERTS","HTTP","SOFTWARE","LICENSE","LOGGING","NETWORK","NTP","POLICY","RESOURCE","SETTINGS","SYSTEM","USER","SNMP","SMTP"];

tableData.auditActionDropdownArr = ["CREATE", "UPDATE", "DELETE"];