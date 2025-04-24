package regexes


import "regexp"


var Patterns = map[string]*regexp.Regexp{
	"google_api": regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	"firebase": regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
	"google_captcha": regexp.MustCompile(`6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`),
	"google_oauth": regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`),
	"amazon_aws_access_key_id": regexp.MustCompile(`A[SK]IA[0-9A-Z]{16}`),
	"amazon_mws_auth_token": regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"amazon_aws_url": regexp.MustCompile(`s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`),
	"facebook_access_token": regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
	"authorization_basic": regexp.MustCompile(`basic [a-zA-Z0-9=:_\+\/-]{5,100}`),
	"authorization_bearer": regexp.MustCompile(`bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`),
	"authorization_api": regexp.MustCompile(`api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}`),
	"mailgun_api_key": regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
	"twilio_api_key": regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
	"twilio_account_sid": regexp.MustCompile(`AC[a-zA-Z0-9_\-]{32}`),
	"twilio_app_sid": regexp.MustCompile(`AP[a-zA-Z0-9_\-]{32}`),
	"paypal_braintree_access_token": regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	"square_oauth_secret": regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`),
	"square_access_token": regexp.MustCompile(`sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`),
	"stripe_standard_api": regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	"stripe_restricted_api": regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
	"github_access_token": regexp.MustCompile(`[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`),
	"rsa_private_key": regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	"ssh_dsa_private_key": regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
	"ssh_ec_private_key": regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	"pgp_private_block": regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	"json_web_token": regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`),
	"slack_token": regexp.MustCompile(`"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"`),
	"ssh_priv_key": regexp.MustCompile(`([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`),
	"Bearer_Auth": regexp.MustCompile(`((?i)bearer\s+([a-zA-Z0-9_\-\.=]+))`),
	"AWS_Client": regexp.MustCompile(`((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|ANPA|ANVA|ASIA)([A-Z0-9]{16}))`),
	"AWS_Secret": regexp.MustCompile(`(?i)(\s+|)["']?((?:aws)?_?(?:secret)?_?(?:access)?_?key)["']?\s*(:|=>|=)\s*["']?(?P<secret>[A-Za-z0-9\/\+=]{40})["']?`),
	"AWS_MWS": regexp.MustCompile(`(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
	"Amazon_AWS_Access_Key_ID": regexp.MustCompile(`([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}`),
	"Amazon_AWS_S3_Bucket": regexp.MustCompile(`//s3-[a-z0-9-]+\.amazonaws\.com/[a-z0-9._-]+`),
	"Discord_Attachments": regexp.MustCompile(`((media|cdn)\.)?(discordapp\.net/attachments|discordapp\.com/attachments)/.+[a-z]`),
	"Discord_BOT_Token": regexp.MustCompile(`((?:N|M|O)[a-zA-Z0-9]{23}\.[a-zA-Z0-9-_]{6}\.[a-zA-Z0-9-_]{27})$`),
	"Bitcoin_Wallet_Address": regexp.MustCompile(`^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$`),
	"Firebase": regexp.MustCompile(`[a-z0-9.-]+\.firebaseio\.com`),
	"GitHub": regexp.MustCompile(`[gG][iI][tT][hH][uU][bB].{0,20}['|"][0-9a-zA-Z]{35,40}['|"]`),
	"Google_API_Key": regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"Heroku_API_Key": regexp.MustCompile(`[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
	"IP_Address": regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`),
	"URL": regexp.MustCompile(`http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!\*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+`),
	"Monero_Wallet_Address": regexp.MustCompile(`4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}`),
	"Mac_Address": regexp.MustCompile(`(([0-9A-Fa-f]{2}[:]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2}|([0-9A-Fa-f]{4}[\.]){2}[0-9A-Fa-f]{4})$`),
	"Mailto": regexp.MustCompile(`mailto:([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+)`),
	"Onion": regexp.MustCompile(`([a-z2-7]{16}|[a-z2-7]{56}).onion`),
	"Telegram_BOT_Token": regexp.MustCompile(`\d{9}:[0-9A-Za-z_-]{35}`),
	"GitHub Generic": regexp.MustCompile(`([gG][iI][tT][hH][uU][bB].*['"][0-9a-zA-Z]{35,40}['"])`),
	"GitHub Personal Token": regexp.MustCompile(`(ghp_[a-zA-Z0-9]{36})`),
	"GitHub Actions Token": regexp.MustCompile(`(ghs_[a-zA-Z0-9]{36})`),
	"GitHub Fine-grained Token": regexp.MustCompile(`(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})`),
	"GitLab Personal Access Token": regexp.MustCompile(`glpat-[0-9a-zA-Z\-_]{20}`),
	"Generic API Key": regexp.MustCompile(`[aA][pP][iI]_?[kK][eE][yY].{0,20}['|"][0-9a-zA-Z]{32,45}['|"]`),
	"Generic Secret": regexp.MustCompile(`[sS][eE][cC][rR][eE][tT].{0,20}['|"][0-9a-zA-Z]{32,45}['|"]`),
	"GenericPass": regexp.MustCompile(`((password|sshpass|senha|pwd|LDAP_REP_PASS|api-key|api_key|creds|credential))`),
	"JDBC Connection String with Credentials": regexp.MustCompile(`(?i)((mongodb(\+srv)?:\/\/[^:]+(?::[^@]+)?@[^\/]+\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|mysql:\/\/jdbc:mysql:\/\/[^:]+:[^@]+@[^:]+:\d+\/[^\s]+|jdbc:(mysql:\/\/[^:]+(?::\d+)?\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|postgresql:\/\/[^:]+(?::\d+)?\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|oracle:thin:@[^:]+(?::\d+)?:[^:]+)))`),
	"jdbc": regexp.MustCompile(`((mongodb(\+srv)?:\/\/[^:]+(?::[^@]+)?@[^\/]+\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|jdbc:(mysql:\/\/[^:]+(?:\d+)?\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|postgresql:\/\/[^:]+(?:\d+)?\/[^?]+(\?[^=&]+=[^&]+(&[^=&]+=[^&]+)*)?|oracle:thin:@[^:]+(?:\d+)?:[^:]+)))`),
	"Google Cloud Platform API Key": regexp.MustCompile(`(AIza[0-9A-Za-z\-_]{35})`),
	"Google Cloud Platform OAuth": regexp.MustCompile(`([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)`),
	"Google Drive API Key": regexp.MustCompile(`(AIza[0-9A-Za-z\-_]{35})`),
	"Google Drive OAuth": regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	"Google (GCP) Service-account": regexp.MustCompile(`"type": "service_account"`),
	"HEROKU_API": regexp.MustCompile(`([hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})`),
	"MAILGUN_API": regexp.MustCompile(`(key-[0-9a-zA-Z]{32})`),
	"MD5 Hash": regexp.MustCompile(`\b([a-f0-9]{32})\b`),
	"SLACK_TOKEN": regexp.MustCompile(`(xox[baprs]-([0-9a-zA-Z]{10,48}))`),
	"SLACK_WEBHOOK": regexp.MustCompile(`(https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})`),
	"SSH (ed25519) Private Key": regexp.MustCompile(`(-----BEGIN OPENSSH PRIVATE KEY-----)`),
	"Twilio API Key": regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
	"Twitter Access Token": regexp.MustCompile(`(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|`){0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:['|"|\n|\r|\s|`|;]|$)`),
	"DigitalOcean Token": regexp.MustCompile(`(do_[a-f0-9]{64})`),
	"Stripe API Key": regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	"Square Access Token": regexp.MustCompile(`(?i)\b(sq0atp-[0-9A-Za-z\-_]{22})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"SendGrid API Key": regexp.MustCompile(`(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})`),
	"Dropbox API Token": regexp.MustCompile(`(sl\.[A-Za-z0-9\-_]{60})`),
	"SSH Private Key": regexp.MustCompile(`(-----BEGIN [A-Z ]*PRIVATE KEY-----)`),
	"Private Key": regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-----[\s\S-]*KEY( BLOCK)?----`),
	"Jenkins_API_Token": regexp.MustCompile(`(?i)(jenkins_api_token[\s]*[:=][\s]*['"](\w{32})['"])`),
	"Jenkins_Crumb": regexp.MustCompile(`(?i)(jenkins-crumb[\s]*[:=][\s]*['"](\w{32})['"])`),
	"MS_Teams_Webhook": regexp.MustCompile(`(https://[a-zA-Z0-9]+\.webhook\.office\.com/webhookb2/[a-zA-Z0-9-]+@[a-zA-Z0-9-]+/IncomingWebhook/[a-zA-Z0-9]+/[a-zA-Z0-9-]+)`),
	"Azure_Sensitive_Info": regexp.MustCompile(`(?i)((azure|connection string|app(?:lication)?\s*(?:id|key|secret)|client\s*(?:id|secret)|access\s*(?:key|token))\s*[:=]\s*['"]([a-zA-Z0-9+/=_\-]{16,})['"](\s|$))`),
	"DBs": regexp.MustCompile(`(?i)((mongodb|mysql|orcl|postgresql|sqlserver).*)`),
	"Mysql Connection String": regexp.MustCompile(`(?i)(?:mysql://)?jdbc:mysql://(?P<username>[^:]+):(?P<password>[^@]+)@(?P<host>[^:/\s]+)(?::(?P<port>\d+))?/(?P<dbname>[^?\s]+)(?:\?.*?)?`),
	"Google Cloud Platform Service Account": regexp.MustCompile(`([0-9]+-[0-9a-zA-Z]{32}@[0-9a-zA-Z]{38})`),
	"Google Cloud Platform Service Account 2": regexp.MustCompile(`([0-9]+-[0-9a-zA-Z]{32}@[0-9a-zA-Z]{32}.apps.googleusercontent.com)`),
	"Google Cloud Platform Service Account 3": regexp.MustCompile(`([0-9]+-[0-9a-zA-Z]{32}@[0-9a-zA-Z]{32}.iam.gserviceaccount.com)`),
	"Google Cloud Platform Service Account 4": regexp.MustCompile(`([0-9]+-[0-9a-zA-Z]{32}@[0-9a-zA-Z]{32}-gcp-sa.iam.gserviceaccount.com)`),
	"Google Cloud Platform Service Account 6": regexp.MustCompile(`([0-9]+-[0-9a-zA-Z]{32}@[0-9a-zA-Z]{32}.gserviceaccount.com)`),
	"AWS AppSync GraphQL Key": regexp.MustCompile(`da2-[a-z0-9]{26}`),
	"Facebook Access Token": regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
	"Facebook Client ID": regexp.MustCompile(`[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}[0-9]{13,17}`),
	"Facebook Client Secret": regexp.MustCompile(`[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}[0-9a-zA-Z]{32}`),
	"Facebook OAuth Access Token": regexp.MustCompile(`[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|"][0-9]{13,17}['|"]`),
	"Facebook OAuth Secret": regexp.MustCompile(`[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|"][0-9a-zA-Z]{32}['|"]`),
	"Facebook OAuth Token": regexp.MustCompile(`[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|"][0-9a-f]{32}['|"]`),
	"LinkedIn Client ID": regexp.MustCompile(`(?i)(?:linkedin|linked-in)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{14})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"LinkedIn Client Secret": regexp.MustCompile(`(?i)(?:linkedin|linked-in)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"LinkedIn OAuth Access Token": regexp.MustCompile(`[lL][iI][nN][kK][eE][dD][iI][nN].{0,20}['|"][0-9a-zA-Z]{16}['|"]`),
	"Google (GCP) OAuth Access Token": regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	"Heroku API Key": regexp.MustCompile(`(?i)(?:heroku)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"JSON Web Token": regexp.MustCompile(`(?i)\b(ey[0-9a-z]{30,34}\.ey[0-9a-z-/_]{30,500}\.[0-9a-zA-Z-/_]{10,200}={0,2})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"JSON Web Token 2": regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*`),
	"Json Web Token": regexp.MustCompile(`eyJhbGciOiJ`),
	"MailChimp API Key": regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
	"Mailgun API Key": regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
	"Password in URL": regexp.MustCompile(`[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s]`),
	"PayPal Braintree Access Token": regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	"PayPal Braintree Sandbox Access Token": regexp.MustCompile(`access_token\$sandbox\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	"PayPal Client ID": regexp.MustCompile(`AdAt[0-9a-z]{32}`),
	"PayPal Secret": regexp.MustCompile(`Esk[0-9a-z]{32}`),
	"Paystack Secret Key": regexp.MustCompile(`sk_test_[0-9a-zA-Z]{30}`),
	"Picatic API Key": regexp.MustCompile(`sk_live_[0-9a-z]{32}`),
	"Slack Webhook": regexp.MustCompile(`https://hooks.slack.com/(services|workflows)/[A-Za-z0-9+/]{44,46}`),
	"Stripe Restricted API Key": regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
	"Stripe Webhook Secret": regexp.MustCompile(`whsec_[0-9a-zA-Z]{24}`),
	"Square OAuth Secret": regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`),
	"Telegram Bot API Key": regexp.MustCompile(`[0-9]+:AA[0-9A-Za-z\-_]{33}`),
	"Twilio Account SID": regexp.MustCompile(`AC[0-9a-fA-F]{32}`),
	"Twilio Auth Token": regexp.MustCompile(`TW[0-9a-fA-F]{32}`),
	"Github Auth Creds": regexp.MustCompile(`https://[a-zA-Z0-9]{40}@github\.com`),
	"Google Gmail API Key": regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"Google Gmail OAuth": regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	"Google OAuth Access Token": regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`),
	"Google YouTube API Key": regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"Google YouTube OAuth": regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	"Twitter OAuth": regexp.MustCompile(`[tT][wW][iI][tT][tT][eE][rR].*['|"][0-9a-zA-Z]{35,44}['|"]`),
	"Twitter Secret": regexp.MustCompile(`[tT][wW][iI][tT][tT][eE][rR].*['|"][0-9a-zA-Z]{35,44}['|"]`),
	"Twitter API Key": regexp.MustCompile(`(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|`){0,5}([a-z0-9]{25})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Twitter API Secret": regexp.MustCompile(`(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|`){0,5}([a-z0-9]{50})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Twitter OAuth Creds": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@twitter\.com`),
	"Twitter OAuth Creds (Legacy)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com`),
	"Twitter OAuth Creds (V2)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2`),
	"Twitter OAuth Creds (V2.1)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2\/1`),
	"Twitter OAuth Creds (V2.2)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2\/2`),
	"Twitter OAuth Creds (V2.3)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2\/3`),
	"Twitter OAuth Creds (V2.4)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2\/4`),
	"Twitter OAuth Creds (V2.5)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2\/5`),
	"Twitter OAuth Creds (V2.6)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2\/6`),
	"Twitter OAuth Creds (V2.7)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2\/7`),
	"Twitter OAuth Creds (V2.8)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2\/8`),
	"Twitter OAuth Creds (V2.9)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2\/9`),
	"Twitter OAuth Creds (V2.10)": regexp.MustCompile(`https:\/\/[a-zA-Z0-9]{40}@api\.twitter\.com\/2\/10`),
	"Apr1 MD5": regexp.MustCompile(`\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}`),
	"MD5": regexp.MustCompile(`[a-f0-9]{32}`),
	"MD5 or SHA1": regexp.MustCompile(`[a-f0-9]{32}|[a-f0-9]{40}`),
	"SHA1": regexp.MustCompile(`[a-f0-9]{40}`),
	"SHA256": regexp.MustCompile(`[a-f0-9]{64}`),
	"SHA512": regexp.MustCompile(`[a-f0-9]{128}`),
	"MD5 or SHA1 or SHA256": regexp.MustCompile(`[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}`),
	"MD5 or SHA1 or SHA256 or SHA512": regexp.MustCompile(`[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}`),
	"Apache SHA": regexp.MustCompile(`\{SHA\}[0-9a-zA-Z/_=]{10,}`),
	"IP V4 Address": regexp.MustCompile(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
	"Slack App Token": regexp.MustCompile(`\bxapp-[0-9]+-[A-Za-z0-9_]+-[0-9]+-[a-f0-9]+\b`),
	"Phone Number": regexp.MustCompile(`\b(\+\d{1,2}\s)?\(\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b`),
	"AWS Access ID": regexp.MustCompile(`\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}\b`),
	"MAC Address": regexp.MustCompile(`\b((([a-zA-z0-9]{2}[-:]){5}([a-zA-z0-9]{2}))|(([a-zA-z0-9]{2}:){5}([a-zA-z0-9]{2})))\b`),
	"Github Classic Personal Access Token": regexp.MustCompile(`\bghp_[A-Za-z0-9_]{36}\b`),
	"Github Fine Grained Personal Access Token": regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`),
	"Github OAuth Access Token": regexp.MustCompile(`\bgho_[A-Za-z0-9_]{36}\b`),
	"Github User to Server Token": regexp.MustCompile(`\bghu_[A-Za-z0-9_]{36}\b`),
	"Github Server to Server Token": regexp.MustCompile(`\bghs_[A-Za-z0-9_]{36}\b`),
	"Stripe Key": regexp.MustCompile(`\b(?:r|s)k_(test|live)_[0-9a-zA-Z]{24}\b`),
	"Firebase Auth Domain": regexp.MustCompile(`\b([a-z0-9-]){1,30}(\.firebaseapp\.com)\b`),
	"Generic Secret Key": regexp.MustCompile(`[sS][eE][cC][rR][eE][tT]_?[kK][eE][yY].{0,20}['|"][0-9a-zA-Z]{32,45}['|"]`),
	"Generic API Secret": regexp.MustCompile(`[aA][pP][iI]_?[sS][eE][cC][rR][eE][tT].{0,20}['|"][0-9a-zA-Z]{32,45}['|"]`),
	"Generic OAuth": regexp.MustCompile(`[aA][pP][iI]_?[sS][eE][cC][rR][eE][tT].{0,20}['|"][0-9a-zA-Z]{32,45}['|"]`),
	"Generic API": regexp.MustCompile(`[aA][pP][iI].{0,20}['|"][0-9a-zA-Z]{32,45}['|"]`),
	"Generic ID": regexp.MustCompile(`[aA][pP][iI]_?[iI][dD].{0,20}['|"][0-9a-zA-Z]{32,45}['|"]`),
	"Generic Password": regexp.MustCompile(`[aA][pP][iI]_?[pP][aA][sS][sS][wW][oO][rR][dD].{0,20}['|"][0-9a-zA-Z]{32,45}['|"]`),
	"AWS API Key": regexp.MustCompile(`((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})`),
	"AWS MWS Auth Token": regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"password": regexp.MustCompile(`/password\s*=\s*([^\s&]+)/i`),
	"pass": regexp.MustCompile(`/pass\s*=\s*([^\s&]+)/i`),
	"pwd": regexp.MustCompile(`/pwd\s*=\s*([^\s&]+)/i`),
	"username": regexp.MustCompile(`/user(?:name)?\s*=\s*([^\s&]+)/i`),
	"email": regexp.MustCompile(`/email\s*=\s*([^\s&]+)/i`),
	"userid": regexp.MustCompile(`/user(?:id)?\s*=\s*([^\s&]+)/i`),
	"login": regexp.MustCompile(`/login\s*=\s*([^\s&]+)/i`),
	"passwd": regexp.MustCompile(`/passwd\s*=\s*([^\s&]+)/i`),
	"passcode": regexp.MustCompile(`/passcode\s*=\s*([^\s&]+)/i`),
	"pw": regexp.MustCompile(`/pw\s*=\s*([^\s&]+)/i`),
	"Email": regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
	"Adafruit API Key": regexp.MustCompile(`(?i)(?:adafruit)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9_-]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Adobe Client ID (OAuth Web)": regexp.MustCompile(`(?i)(?:adobe)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Adobe Client Secret": regexp.MustCompile(`(?i)\b((p8e-)(?i)[a-z0-9]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Age Secret Key": regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`),
	"Airtable API Key": regexp.MustCompile(`(?i)(?:airtable)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{17})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Algolia API Key": regexp.MustCompile(`(?i)(?:algolia)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Alibaba AccessKey ID": regexp.MustCompile(`(?i)\b((LTAI)(?i)[a-z0-9]{20})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Alibaba Secret Key": regexp.MustCompile(`(?i)(?:alibaba)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Asana Client ID": regexp.MustCompile(`(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([0-9]{16})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"Asana Client Secret": regexp.MustCompile(`(?i)(?:asana)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"Atlassian API token": regexp.MustCompile(`(?i)(?:atlassian|confluence|jira)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"AWS": regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
	"AWS MWS Key": regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"Beamer API token": regexp.MustCompile(`(?i)(?:beamer)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}(b_[a-z0-9=_\-]{44})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Bitbucket Client ID": regexp.MustCompile(`(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Bitbucket Client Secret": regexp.MustCompile(`(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9=_\-]{64})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Bittrex Access Key": regexp.MustCompile(`(?i)(?:bittrex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Clojars API token": regexp.MustCompile(`(?i)(CLOJARS_)[a-z0-9]{60}`),
	"Codecov Access Token": regexp.MustCompile(`(?i)(?:codecov)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Coinbase Access Token": regexp.MustCompile(`(?i)(?:coinbase)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9_-]{64})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Confluent Access Token": regexp.MustCompile(`(?i)(?:confluent)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([a-z0-9]{16})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"Confluent Secret Key": regexp.MustCompile(`(?i)(?:confluent)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"Contentful Delivery API Token": regexp.MustCompile(`(?i)(?:contentful)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9=_\-]{43})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Databricks API Token": regexp.MustCompile(`(?i)\b(dapi[a-h0-9]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Datadog Access Token": regexp.MustCompile(`(?i)(?:datadog)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"DigitalOcean OAuth Access Token": regexp.MustCompile(`(?i)\b(doo_v1_[a-f0-9]{64})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"DigitalOcean Personal Access Token": regexp.MustCompile(`(?i)\b(dop_v1_[a-f0-9]{64})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"DigitalOcean OAuth Refresh Token": regexp.MustCompile(`(?i)\b(dor_v1_[a-f0-9]{64})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Discord API Key": regexp.MustCompile(`(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-f0-9]{64})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Discord Client ID": regexp.MustCompile(`(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([0-9]{18})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Discord Client Secret": regexp.MustCompile(`(?i)(?:discord)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Doppler API Token": regexp.MustCompile(`(dp\.pt\.)(?i)[a-z0-9]{43}`),
	"DroneCI Access Token": regexp.MustCompile(`(?i)(?:droneci)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Dropbox API Secret": regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{15})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Dropbox Long-Lived API Token": regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Dropbox Short-Lived API Token": regexp.MustCompile(`(?i)(?:dropbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}(sl\.[a-z0-9\-=_]{135})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Duffel API Token": regexp.MustCompile(`duffel_(test|live)_(?i)[a-z0-9_\-=]{43}`),
	"Dynatrace API Token": regexp.MustCompile(`dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`),
	"EasyPost API Token": regexp.MustCompile(`EZAK(?i)[a-z0-9]{54}`),
	"EasyPost Test API Token": regexp.MustCompile(`EZTK(?i)[a-z0-9]{54}`),
	"Etsy Access Token": regexp.MustCompile(`(?i)(?:etsy)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Facebook API Key": regexp.MustCompile(`(?i)(?:facebook)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Fastly API Key": regexp.MustCompile(`(?i)(?:fastly)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"GitHub App Token": regexp.MustCompile(`(ghu|ghs)_[0-9a-zA-Z]{36}`),
	"GitHub Fine-Grained Personal Access Token": regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{82}`),
	"GitHub OAuth Access Token": regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
	"GitHub Personal Access Token": regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
	"GitHub Refresh Token": regexp.MustCompile(`ghr_[0-9a-zA-Z]{36}`),
	"GitLab Pipeline Trigger Token": regexp.MustCompile(`glptt-[0-9a-f]{40}`),
	"GitLab Runner Registration Token": regexp.MustCompile(`GR1348941[0-9a-zA-Z\-_]{20}`),
	"Gitter Access Token": regexp.MustCompile(`(?i)(?:gitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9_-]{40})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"GoCardless API Token": regexp.MustCompile(`(?i)(?:gocardless)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}(live_(?i)[a-z0-9\-_=]{40})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Grafana api key (or Grafana cloud api key)": regexp.MustCompile(`(?i)(eyJrIjoi[A-Za-z0-9]{70,400}={0,2})(?:['|"|
||\s|\x60|;]|$)`),
	"Grafana cloud api token": regexp.MustCompile(`(?i)(glc_[A-Za-z0-9+/]{32,400}={0,2})(?:['|"|
||\s|\x60|;]|$)`),
	"Grafana service account token": regexp.MustCompile(`(?i)(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:['|"|
||\s|\x60|;]|$)`),
	"HashiCorp Terraform user/org API Token": regexp.MustCompile(`(?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}`),
	"HubSpot API Token": regexp.MustCompile(`(?i)(?:hubspot)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Intercom API Token": regexp.MustCompile(`(?i)(?:intercom)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9=_\-]{60})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Kraken Access Token": regexp.MustCompile(`(?i)(?:kraken)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9\/=_\+\-]{80,90})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Kucoin Access Token": regexp.MustCompile(`(?i)(?:kucoin)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-f0-9]{24})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Kucoin Secret Key": regexp.MustCompile(`(?i)(?:kucoin)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Launchdarkly Access Token": regexp.MustCompile(`(?i)(?:launchdarkly)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9=_\-]{40})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Linear API Token": regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
	"Linear Client Secret": regexp.MustCompile(`(?i)(?:linear)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Lob API Key": regexp.MustCompile(`(?i)(?:lob)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}((live|test)_[a-f0-9]{35})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Lob Publishable API Key": regexp.MustCompile(`(?i)(?:lob)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}((test|live)_pub_[a-f0-9]{31})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Mailchimp API Key": regexp.MustCompile(`(?i)(?:mailchimp)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{32}-us20)(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Mailgun Private API Token": regexp.MustCompile(`(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(key-[a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Mailgun Public Validation Key": regexp.MustCompile(`(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(pubkey-[a-f0-9]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Mailgun Webhook Signing Key": regexp.MustCompile(`(?i)(?:mailgun)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"MapBox API Token": regexp.MustCompile(`(?i)(?:mapbox)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(pk\.[a-z0-9]{60}\.[a-z0-9]{22})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Mattermost Access Token": regexp.MustCompile(`(?i)(?:mattermost)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{26})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"MessageBird API Token": regexp.MustCompile(`(?i)(?:messagebird|message-bird|message_bird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{25})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"MessageBird Client ID": regexp.MustCompile(`(?i)(?:messagebird|message-bird|message_bird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Microsoft Teams Webhook": regexp.MustCompile(`https:\/\/outlook\.office\.com\/webhook\/[A-Za-z0-9\-@]+\/IncomingWebhook\/[A-Za-z0-9\-]+\/[A-Za-z0-9\-]+`),
	"Netlify Access Token": regexp.MustCompile(`(?i)(?:netlify)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{40,46})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"New Relic ingest browser API token": regexp.MustCompile(`(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(NRJS-[a-f0-9]{19})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"New Relic user API ID": regexp.MustCompile(`(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"New Relic user API Key": regexp.MustCompile(`(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(NRAK-[a-z0-9]{27})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"npm access token": regexp.MustCompile(`(?i)\b(npm_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Nytimes Access Token": regexp.MustCompile(`(?i)(?:nytimes|new-york-times|newyorktimes)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{32})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Okta Access Token": regexp.MustCompile(`(?i)(?:okta)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9=_\-]{42})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Plaid API Token": regexp.MustCompile(`(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Plaid Client ID": regexp.MustCompile(`(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{24})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Plaid Secret key": regexp.MustCompile(`(?i)(?:plaid)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{30})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"PlanetScale API token": regexp.MustCompile(`(?i)\b(pscale_tkn_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"PlanetScale OAuth token": regexp.MustCompile(`(?i)\b(pscale_oauth_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"PlanetScale password": regexp.MustCompile(`(?i)\b(pscale_pw_(?i)[a-z0-9=\-_\.]{32,64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Postman API token": regexp.MustCompile(`(?i)\b(PMAK-(?i)[a-f0-9]{24}-[a-f0-9]{34})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Prefect API token": regexp.MustCompile(`(?i)\b(pnu_[a-z0-9]{36})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Pulumi API token": regexp.MustCompile(`(?i)\b(pul-[a-f0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"PyPI upload token": regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
	"RapidAPI Access Token": regexp.MustCompile(`(?i)(?:rapidapi)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9_-]{50})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Readme API token": regexp.MustCompile(`(?i)\b(rdme_[a-z0-9]{70})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Rubygem API token": regexp.MustCompile(`(?i)\b(rubygems_[a-f0-9]{48})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Sendbird Access ID": regexp.MustCompile(`(?i)(?:sendbird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Sendbird Access Token": regexp.MustCompile(`(?i)(?:sendbird)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"SendGrid API token": regexp.MustCompile(`(?i)\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Sendinblue API token": regexp.MustCompile(`(?i)\b(xkeysib-[a-f0-9]{64}-(?i)[a-z0-9]{16})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Sentry Access Token": regexp.MustCompile(`(?i)(?:sentry)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Shippo API token": regexp.MustCompile(`(?i)\b(shippo_(live|test)_[a-f0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Shopify access token": regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
	"Shopify custom access token": regexp.MustCompile(`shpca_[a-fA-F0-9]{32}`),
	"Shopify private app access token": regexp.MustCompile(`shppa_[a-fA-F0-9]{32}`),
	"Shopify shared secret": regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`),
	"Sidekiq Secret": regexp.MustCompile(`(?i)(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Sidekiq Sensitive URL": regexp.MustCompile(`(?i)(http(?:s??)://)([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[/|\#|\?|:]|$)`),
	"Slack token": regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})`),
	"Squarespace Access Token": regexp.MustCompile(`(?i)(?:squarespace)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|"|\n|\r|\s|\x60|;]|$)`),
	"Stripe": regexp.MustCompile(`(?i)(sk|pk)_(test|live)_[0-9a-z]{10,32}`),
	"SumoLogic Access ID": regexp.MustCompile(`(?i)(?:sumo)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{14})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"SumoLogic Access Token": regexp.MustCompile(`(?i)(?:sumo)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{64})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Telegram Bot API Token": regexp.MustCompile(`(?i)(?:^|[^0-9])([0-9]{5,16}:A[a-zA-Z0-9_\-]{34})(?:$|[^a-zA-Z0-9_\-])`),
	"Travis CI Access Token": regexp.MustCompile(`(?i)(?:travis)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{22})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"Twitch API token": regexp.MustCompile(`(?i)(?:twitch)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|`){0,5}([a-z0-9]{30})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Twitter Access Secret": regexp.MustCompile(`(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|`){0,5}([a-z0-9]{45})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Twitter Bearer Token": regexp.MustCompile(`(?i)(?:twitter)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|`){0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Typeform API token": regexp.MustCompile(`(?i)(?:typeform)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|`){0,5}(tfp_[a-z0-9\-_\.]{59})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Vault Batch Token": regexp.MustCompile(`(?i)(hvb\.[a-z0-9_-]{138,212})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Vault Service Token": regexp.MustCompile(`(?i)(hvs\.[a-z0-9_-]{90,100})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Yandex Access Token": regexp.MustCompile(`(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|`){0,5}(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Yandex API Key": regexp.MustCompile(`(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|`){0,5}(AQVN[A-Za-z0-9_\-]{35,38})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Yandex AWS Access Token": regexp.MustCompile(`(?i)(?:yandex)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|`){0,5}(YC[a-zA-Z0-9_\-]{38})(?:['|"|\n|\r|\s|`|;]|$)`),
	"Zendesk Secret Key": regexp.MustCompile(`(?i)(?:zendesk)(?:[0-9a-z\-_\t .]{0,20})(?:[\s\|']|[\s\|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|\"|\n|\r|\s|\x60|;]|$)`),
	"amazon_aws_url2": regexp.MustCompile(`(?:[a-zA-Z0-9-._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-._]+|s3-[a-zA-Z0-9-._/]+|s3\.amazonaws\.com/[a-zA-Z0-9-._]+|s3\.console\.aws\.amazon\.com/s3/buckets/[a-zA-Z0-9-._]+)`),
	"Faster_api_key": regexp.MustCompile(`"x-fstr-application-key"\s*:\s*"[a-f0-9-]{36}"`),
	"CLEARSALE_APP_ID": regexp.MustCompile(`CLEARSALE_APP_ID\s*:\s*"([a-zA-Z0-9]+)"`),
	"CYBERSOURCE_APP_ID": regexp.MustCompile(`CYBERSOURCE_APP_ID\s*:\s*"([a-zA-Z0-9]+)"`),
	"SENDBIRD_APP_ID": regexp.MustCompile(`SENDBIRD_APP_ID\s*:\s*"([a-zA-Z0-9-]+)"`),
	"BUGSNAG_API_KEY": regexp.MustCompile(`BUGSNAG_API_KEY\s*:\s*"([a-f0-9]{32})"`),
	"WSV3_ACCESS_KEY": regexp.MustCompile(`WSV3_ACCESS_KEY\s*:\s*"([a-f0-9-]+)"`),
	"WSV3_SECRET_KEY": regexp.MustCompile(`WSV3_SECRET_KEY\s*:\s*"([a-f0-9-]+)"`),
	"GOOGLE_AUTH_KEY": regexp.MustCompile(`GOOGLE_AUTH_KEY\s*:\s*"([a-zA-Z0-9.-_]+)"`),
	"GOOGLE_API_KEY": regexp.MustCompile(`GOOGLE_API_KEY\s*:\s*"([A-Za-z0-9-_]{39})"`),
	"GOOGLE_ANALYTICS_ID": regexp.MustCompile(`GOOGLE_ANALYTICS_ID\s*:\s*"(UA-[0-9-]+)"`),
	"GOOGLE_TAG_MANAGER_ID": regexp.MustCompile(`GOOGLE_TAG_MANAGER_ID\s*:\s*"(GTM-[A-Z0-9]+)"`),
	"GOOGLE_OPTIMIZE_ID": regexp.MustCompile(`GOOGLE_OPTIMIZE_ID\s*:\s*"(GTM-[A-Z0-9]+)"`),
	"ADDRESS_X_APPLICATION_KEY": regexp.MustCompile(`ADDRESS_X_APPLICATION_KEY\s*:\s*"([a-zA-Z0-9]+)"`),
	"FACEBOOK_APP_ID": regexp.MustCompile(`FACEBOOK_APP_ID\s*:\s*"([0-9]+)"`),
	"FASTER_APP_KEY": regexp.MustCompile(`FASTER_APP_KEY\s*:\s*"([a-zA-Z0-9-]+)"`),
	"FASTER_SECRET_KEY": regexp.MustCompile(`FASTER_SECRET_KEY\s*:\s*"([a-zA-Z0-9-]+)"`),
	"TRACKJS_NAME": regexp.MustCompile(`TRACKJS_NAME\s*:\s*"([^"]+)"`),
	"Possible Leak - Bucketeer AWS Secret Access Key": regexp.MustCompile(`(?i)["']?bucketeer[-]?aws[-]?secret[-]?access[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bucketeer AWS Access Key ID": regexp.MustCompile(`(?i)["']?bucketeer[-]?aws[-]?access[-]?key[-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - BrowserStack Access Key": regexp.MustCompile(`(?i)["']?browserstack[-]?access[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Browser Stack Access Key": regexp.MustCompile(`(?i)["']?browser[-]?stack[-]?access[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Brackets Repo OAuth Token": regexp.MustCompile(`(?i)["']?brackets[-]?repo[-]?oauth[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bluemix Username": regexp.MustCompile(`(?i)["']?bluemix[_-]?username["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bluemix Password (pwd)": regexp.MustCompile(`(?i)["']?bluemix[_-]?pwd["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bluemix Password": regexp.MustCompile(`(?i)["']?bluemix[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bluemix Production Password": regexp.MustCompile(`(?i)["']?bluemix[-]?pass[-]?prod["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub Token": regexp.MustCompile(`(?i)["']?github[_-]?token["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub Repo": regexp.MustCompile(`(?i)["']?github[_-]?repo["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub Release Token": regexp.MustCompile(`(?i)["']?github[-]?release[-]?token["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - YouTube Server API Key": regexp.MustCompile(`(?i)["']?yt[-]?server[-]?api[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - YouTube Partner Refresh Token": regexp.MustCompile(`(?i)["']?yt[-]?partner[-]?refresh[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - YouTube Partner Client Secret": regexp.MustCompile(`(?i)["']?yt[-]?partner[-]?client[_-]?secret["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - YouTube Client Secret": regexp.MustCompile(`(?i)["']?yt[-]?client[-]?secret["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - YouTube API Key": regexp.MustCompile(`(?i)["']?yt[-]?api[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - YouTube Account Refresh Token": regexp.MustCompile(`(?i)["']?yt[-]?account[-]?refresh[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - YouTube Account Client Secret": regexp.MustCompile(`(?i)["']?yt[-]?account[-]?client[_-]?secret["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Yangshun GitHub Token": regexp.MustCompile(`(?i)["']?yangshun[-]?gh[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Yangshun GitHub Password": regexp.MustCompile(`(?i)["']?yangshun[-]?gh[-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Google APIs Key": regexp.MustCompile(`(?i)["']?www[-]?googleapis[-]?com["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - WebPageTest SSH Private Key (Base64)": regexp.MustCompile(`(?i)["']?wpt[-]?ssh[-]?private[-]?key[-]?base64["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - BundleSize GitHub Token": regexp.MustCompile(`(?i)["']?bundlesize[-]?github[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Built Branch Deploy Key": regexp.MustCompile(`(?i)["']?built[-]?branch[-]?deploy[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub Password (pwd)": regexp.MustCompile(`(?i)["']?github[_-]?pwd["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub Password": regexp.MustCompile(`(?i)["']?github[_-]?password["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub OAuth Token": regexp.MustCompile(`(?i)["']?github[-]?oauth[-]?token["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub OAuth": regexp.MustCompile(`(?i)["']?github[_-]?oauth["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub Key": regexp.MustCompile(`(?i)["']?github[_-]?key["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub Hunter Username": regexp.MustCompile(`(?i)["']?github[-]?hunter[-]?username["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub Hunter Token": regexp.MustCompile(`(?i)["']?github[-]?hunter[-]?token["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub Deployment Token": regexp.MustCompile(`(?i)["']?github[-]?deployment[-]?token["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Argos Token": regexp.MustCompile(`(?i)["']?argos[_-]?token["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Apple ID Password": regexp.MustCompile(`(?i)["']?apple[-]?id[-]?password["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - App Client Secret": regexp.MustCompile(`(?i)["']?appclientsecret["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - App Token": regexp.MustCompile(`(?i)["']?app[_-]?token["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - App Secret": regexp.MustCompile(`(?i)["']?app[_-]?secrete["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - App Report Token Key": regexp.MustCompile(`(?i)["']?app[-]?report[-]?token[_-]?key["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - App Bucket Permission": regexp.MustCompile(`(?i)["']?app[-]?bucket[-]?perm["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - API Gateway Access Token": regexp.MustCompile(`(?i)["']?apigw[-]?access[-]?token["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Apiary API Key": regexp.MustCompile(`(?i)["']?apiary[-]?api[-]?key["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - API Secret": regexp.MustCompile(`(?i)["']?api[_-]?secret["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - API Key SID": regexp.MustCompile(`(?i)["']?api[-]?key[-]?sid["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - API Key Secret": regexp.MustCompile(`(?i)["']?api[-]?key[-]?secret["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - API Key": regexp.MustCompile(`(?i)["']?api[_-]?key["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - AOS Security Key": regexp.MustCompile(`(?i)["']?aos[_-]?sec["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - AOS Key": regexp.MustCompile(`(?i)["']?aos[_-]?key["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Ansible Vault Password": regexp.MustCompile(`(?i)["']?ansible[-]?vault[-]?password["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Android Docs Deploy Token": regexp.MustCompile(`(?i)["']?android[-]?docs[-]?deploy[_-]?token["']?\s*[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - AWS SES Access Key ID": regexp.MustCompile(`(?i)["']?aws[-]?ses[-]?access[-]?key[-]?id["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - AWS Secrets": regexp.MustCompile(`(?i)["']?aws[_-]?secrets["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - AWS Secret Key": regexp.MustCompile(`(?i)["']?aws[_-]?secret[_-]?(?:secret|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)["']?[^\S\r\n]*[=:][^\S\r\n]*["']?([\w-]+)["']?`),
	"Possible Leak - AWS Secret Access Key": regexp.MustCompile(`(?i)["']?aws[-]?secret[-]?access[_-]?key["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - AWS Secret": regexp.MustCompile(`(?i)["']?aws[_-]?secret["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - AWS Key": regexp.MustCompile(`(?i)["']?aws[_-]?key["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - AWS Config Secret Access Key": regexp.MustCompile(`(?i)["']?aws[-]?config[-]?secretaccesskey["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - AWS Config Access Key ID": regexp.MustCompile(`(?i)["']?aws[-]?config[-]?accesskeyid["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - AWS Access Key ID": regexp.MustCompile(`(?i)["']?awsaccesskeyid["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - AWS Access Key": regexp.MustCompile(`(?i)["']?aws[-]?access[-]?key["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - AWS Access": regexp.MustCompile(`(?i)["']?aws[_-]?access["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Author NPM API Key": regexp.MustCompile(`(?i)["']?author[-]?npm[-]?api[_-]?key["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Author Email Address": regexp.MustCompile(`(?i)["']?author[-]?email[-]?addr["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Auth0 Client Secret": regexp.MustCompile(`(?i)["']?auth0[-]?client[-]?secret["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Auth0 API Client Secret": regexp.MustCompile(`(?i)["']?auth0[-]?api[-]?clientsecret["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Auth Token": regexp.MustCompile(`(?i)["']?auth[_-]?token["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Assistant IAM API Key": regexp.MustCompile(`(?i)["']?assistant[-]?iam[-]?apikey["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Artifacts Secret": regexp.MustCompile(`(?i)["']?artifacts[_-]?secret["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Artifacts Key": regexp.MustCompile(`(?i)["']?artifacts[_-]?key["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Artifacts Bucket": regexp.MustCompile(`(?i)["']?artifacts[_-]?bucket["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Artifacts AWS Secret Access Key": regexp.MustCompile(`(?i)["']?artifacts[-]?aws[-]?secret[-]?access[-]?key["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Artifacts AWS Access Key ID": regexp.MustCompile(`(?i)["']?artifacts[-]?aws[-]?access[-]?key[-]?id["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Artifactory Key": regexp.MustCompile(`(?i)["']?artifactory[_-]?key["']?\s*[:=]\s*["']?[\w-]+["']?`),
	"Possible Leak - Consumer Key": regexp.MustCompile(`(?i)["']?consumerkey["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Consumer Key (Alternative)": regexp.MustCompile(`(?i)["']?consumer[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Conekta API Key": regexp.MustCompile(`(?i)["']?conekta[_-]?apikey["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Coding Token": regexp.MustCompile(`(?i)["']?coding[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Codecov Token": regexp.MustCompile(`(?i)["']?codecov[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CodeClimate Repo Token": regexp.MustCompile(`(?i)["']?codeclimate[-]?repo[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Codacy Project Token": regexp.MustCompile(`(?i)["']?codacy[-]?project[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CocoaPods Trunk Token": regexp.MustCompile(`(?i)["']?cocoapods[-]?trunk[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CocoaPods Trunk Email": regexp.MustCompile(`(?i)["']?cocoapods[-]?trunk[-]?email["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CN Secret Access Key": regexp.MustCompile(`(?i)["']?cn[-]?secret[-]?access[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CN Access Key ID": regexp.MustCompile(`(?i)["']?cn[-]?access[-]?key[_-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CLU SSH Private Key (Base64)": regexp.MustCompile(`(?i)["']?clu[-]?ssh[-]?private[-]?key[-]?base64["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CLU Repo URL": regexp.MustCompile(`(?i)["']?clu[-]?repo[-]?url["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudinary URL (Staging)": regexp.MustCompile(`(?i)["']?cloudinary[-]?url[-]?staging["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudinary URL": regexp.MustCompile(`(?i)["']?cloudinary[_-]?url["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudflare Email": regexp.MustCompile(`(?i)["']?cloudflare[_-]?email["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudflare Auth Key": regexp.MustCompile(`(?i)["']?cloudflare[-]?auth[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudflare Auth Email": regexp.MustCompile(`(?i)["']?cloudflare[-]?auth[-]?email["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudflare API Key": regexp.MustCompile(`(?i)["']?cloudflare[-]?api[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudant Service Database": regexp.MustCompile(`(?i)["']?cloudant[-]?service[-]?database["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudant Processed Database": regexp.MustCompile(`(?i)["']?cloudant[-]?processed[-]?database["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudant Password": regexp.MustCompile(`(?i)["']?cloudant[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudant Parsed Database": regexp.MustCompile(`(?i)["']?cloudant[-]?parsed[-]?database["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudant Order Database": regexp.MustCompile(`(?i)["']?cloudant[-]?order[-]?database["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudant Instance": regexp.MustCompile(`(?i)["']?cloudant[_-]?instance["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudant Database": regexp.MustCompile(`(?i)["']?cloudant[_-]?database["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudant Audited Database": regexp.MustCompile(`(?i)["']?cloudant[-]?audited[-]?database["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloudant Archived Database": regexp.MustCompile(`(?i)["']?cloudant[-]?archived[-]?database["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cloud API Key": regexp.MustCompile(`(?i)["']?cloud[-]?api[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Clojars Password": regexp.MustCompile(`(?i)["']?clojars[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Client Secret": regexp.MustCompile(`(?i)["']?client[_-]?secret["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CLI E2E CMA Token": regexp.MustCompile(`(?i)["']?cli[-]?e2e[-]?cma[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Claimr Token": regexp.MustCompile(`(?i)["']?claimr[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Claimr Superuser": regexp.MustCompile(`(?i)["']?claimr[_-]?superuser["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Claimr DB": regexp.MustCompile(`(?i)["']?claimr[_-]?db["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Claimr Database": regexp.MustCompile(`(?i)["']?claimr[_-]?database["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CI User Token": regexp.MustCompile(`(?i)["']?ci[-]?user[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CI Server Name": regexp.MustCompile(`(?i)["']?ci[-]?server[-]?name["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CI Registry User": regexp.MustCompile(`(?i)["']?ci[-]?registry[-]?user["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CI Project URL": regexp.MustCompile(`(?i)["']?ci[-]?project[-]?url["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CI Deploy Password": regexp.MustCompile(`(?i)["']?ci[-]?deploy[-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Chrome Refresh Token": regexp.MustCompile(`(?i)["']?chrome[-]?refresh[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Chrome Client Secret": regexp.MustCompile(`(?i)["']?chrome[-]?client[-]?secret["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cheverny Token": regexp.MustCompile(`(?i)["']?cheverny[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - CF Password": regexp.MustCompile(`(?i)["']?cf[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Certificate Password": regexp.MustCompile(`(?i)["']?certificate[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Censys Secret": regexp.MustCompile(`(?i)["']?censys[_-]?secret["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cattle Secret Key": regexp.MustCompile(`(?i)["']?cattle[-]?secret[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cattle Agent Instance Auth": regexp.MustCompile(`(?i)["']?cattle[-]?agent[-]?instance[_-]?auth["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cattle Access Key": regexp.MustCompile(`(?i)["']?cattle[-]?access[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cargo Token": regexp.MustCompile(`(?i)["']?cargo[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Cache S3 Secret Key": regexp.MustCompile(`(?i)["']?cache[-]?s3[-]?secret[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - BX Username": regexp.MustCompile(`(?i)["']?bx[_-]?username["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - BX Password": regexp.MustCompile(`(?i)["']?bx[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bundlesize GitHub Token": regexp.MustCompile(`(?i)["']?bundlesize[-]?github[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bluemix PWD": regexp.MustCompile(`(?i)["']?bluemix[_-]?pwd["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bluemix Pass Prod": regexp.MustCompile(`(?i)["']?bluemix[-]?pass[-]?prod["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bluemix Pass": regexp.MustCompile(`(?i)["']?bluemix[_-]?pass["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bluemix Auth": regexp.MustCompile(`(?i)["']?bluemix[_-]?auth["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bluemix API Key": regexp.MustCompile(`(?i)["']?bluemix[-]?api[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bintray Key": regexp.MustCompile(`(?i)["']?bintraykey["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bintray Token": regexp.MustCompile(`(?i)["']?bintray[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bintray Key (Alternative)": regexp.MustCompile(`(?i)["']?bintray[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bintray GPG Password": regexp.MustCompile(`(?i)["']?bintray[-]?gpg[-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Bintray API Key": regexp.MustCompile(`(?i)["']?bintray[-]?api[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - B2 Bucket": regexp.MustCompile(`(?i)["']?b2[_-]?bucket["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - B2 App Key": regexp.MustCompile(`(?i)["']?b2[-]?app[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - AWS China Secret Access Key": regexp.MustCompile(`(?i)["']?awscn[-]?secret[-]?access[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - AWS China Access Key ID": regexp.MustCompile(`(?i)["']?awscn[-]?access[-]?key[_-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - AWS SES Secret Access Key": regexp.MustCompile(`(?i)["']?aws[-]?ses[-]?secret[-]?access[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - GitHub API Key": regexp.MustCompile(`(?i)["']?gh[-]?api[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Google Cloud Storage Bucket": regexp.MustCompile(`(?i)["']?gcs[_-]?bucket["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Google Container Registry Password": regexp.MustCompile(`(?i)["']?gcr[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Google Cloud Service Key": regexp.MustCompile(`(?i)["']?gcloud[-]?service[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Google Cloud Project": regexp.MustCompile(`(?i)["']?gcloud[_-]?project["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Google Cloud Bucket": regexp.MustCompile(`(?i)["']?gcloud[_-]?bucket["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - FTP Username": regexp.MustCompile(`(?i)["']?ftp[_-]?username["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - FTP User": regexp.MustCompile(`(?i)["']?ftp[_-]?user["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - FTP Password (Short)": regexp.MustCompile(`(?i)["']?ftp[_-]?pw["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - FTP Password": regexp.MustCompile(`(?i)["']?ftp[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - FTP Login": regexp.MustCompile(`(?i)["']?ftp[_-]?login["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - FTP Host": regexp.MustCompile(`(?i)["']?ftp[_-]?host["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - FOSSA API Key": regexp.MustCompile(`(?i)["']?fossa[-]?api[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Flickr API Secret": regexp.MustCompile(`(?i)["']?flickr[-]?api[-]?secret["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Flickr API Key": regexp.MustCompile(`(?i)["']?flickr[-]?api[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Env Secret Access Key": regexp.MustCompile(`(?i)["']?env[-]?secret[-]?access[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Env Secret": regexp.MustCompile(`(?i)["']?env[_-]?secret["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Env Key": regexp.MustCompile(`(?i)["']?env[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Env Heroku API Key": regexp.MustCompile(`(?i)["']?env[-]?heroku[-]?api[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Env GitHub OAuth Token": regexp.MustCompile(`(?i)["']?env[-]?github[-]?oauth[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - End User Password": regexp.MustCompile(`(?i)["']?end[-]?user[-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Encryption Password": regexp.MustCompile(`(?i)["']?encryption[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Elasticsearch Password": regexp.MustCompile(`(?i)["']?elasticsearch[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Elastic Cloud Auth": regexp.MustCompile(`(?i)["']?elastic[-]?cloud[-]?auth["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dsonar Project Key": regexp.MustCompile(`(?i)["']?dsonar[_-]?projectkey["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dsonar Login": regexp.MustCompile(`(?i)["']?dsonar[_-]?login["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dsonar Host": regexp.MustCompile(`(?i)["']?dsonar[_-]?host["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dsonar Password": regexp.MustCompile(`(?i)["']?dsonar[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dotenv API Key": regexp.MustCompile(`(?i)["']?dotenv[_-]?apikey["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Digicert API Key": regexp.MustCompile(`(?i)["']?digicert[_-]?apikey["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Digicert API Key (Alt)": regexp.MustCompile(`(?i)["']?digicert[-]?api[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - DigitalOcean Access Token": regexp.MustCompile(`(?i)["']?digitalocean[-]?access[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - DigitalOcean Key": regexp.MustCompile(`(?i)["']?digital[-]?ocean[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - DigitalOcean API Key": regexp.MustCompile(`(?i)["']?digital[-]?ocean[-]?apikey["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - DigitalOcean Access Key": regexp.MustCompile(`(?i)["']?digital[-]?ocean[-]?access[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - DevTools Honeycomb API Key": regexp.MustCompile(`(?i)["']?dev[-]?tools[-]?honeycomb[-]?api[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev.to API Key": regexp.MustCompile(`(?i)["']?dev[-]?to[-]?api[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Rake API Key": regexp.MustCompile(`(?i)["']?dev[-]?rake[-]?api[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev RabbitMQ Password": regexp.MustCompile(`(?i)["']?dev[-]?rabbitmq[-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev RabbitMQ Login": regexp.MustCompile(`(?i)["']?dev[-]?rabbitmq[-]?login["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev RabbitMQ Host": regexp.MustCompile(`(?i)["']?dev[-]?rabbitmq[-]?host["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev RabbitMQ Admin Password": regexp.MustCompile(`(?i)["']?dev[-]?rabbitmq[-]?admin[_-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev RabbitMQ Admin Login": regexp.MustCompile(`(?i)["']?dev[-]?rabbitmq[-]?admin[_-]?login["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev RabbitMQ Admin Host": regexp.MustCompile(`(?i)["']?dev[-]?rabbitmq[-]?admin[_-]?host["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Postgres Password": regexp.MustCompile(`(?i)["']?dev[-]?postgres[-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Postgres Host": regexp.MustCompile(`(?i)["']?dev[-]?postgres[-]?host["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev MySQL Password": regexp.MustCompile(`(?i)["']?dev[-]?mysql[-]?password["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev MySQL Host": regexp.MustCompile(`(?i)["']?dev[-]?mysql[-]?host["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft API Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?api[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access Token": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access ID": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[_-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access Credentials": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[_-]?credentials["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access Code": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[_-]?code["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access Auth": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[_-]?auth["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access API Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[_-]?apikey["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access Token Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[-]?token[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access Token ID": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[-]?token[-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access Key ID": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[-]?key[-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access Key Credential": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[-]?key[-]?credential["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access ID Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[-]?id[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Access Credential Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?access[-]?credential[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account Secret Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?secret[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account Key ID": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?key[-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account Credentials Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?credentials[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account Auth Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?auth[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account Access Token Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?access[-]?token[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account Access ID Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?access[-]?id[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account Key ID Credential": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?key[-]?id[_-]?credential["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account Auth Token Key": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?auth[-]?token[_-]?key["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key ID": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[_-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Credential": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[_-]?credential["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Auth": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[_-]?auth["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Access Token": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?access[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Access ID": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?access[-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Access Credential": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?access[-]?credential["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Access Auth": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?access[-]?auth["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Auth Token": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?auth[-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Auth ID": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?auth[-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Auth Credential": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?auth[-]?credential["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Auth Access Token": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?auth[-]?access[_-]?token["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Auth Access ID": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?auth[-]?access[_-]?id["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Auth Access Credential": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?auth[-]?access[_-]?credential["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Auth Access Auth": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?auth[-]?access[_-]?auth["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Dev Microsoft Account APIKey Key Auth Access APIKey": regexp.MustCompile(`(?i)["']?dev[-]?microsoft[-]?account[-]?apikey[-]?key[-]?auth[-]?access[_-]?apikey["']?[^\S\r\n][=:][^\S\r\n]["']?[\w-]+["']?`),
	"Possible Leak - Netlify API Key": regexp.MustCompile(`(?i)["']?netlify[-]?api[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Native Events": regexp.MustCompile(`(?i)["']?nativeevents["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MySQL Secret": regexp.MustCompile(`(?i)["']?mysqlsecret["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MySQL Master User": regexp.MustCompile(`(?i)["']?mysqlmasteruser["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MySQL Username": regexp.MustCompile(`(?i)["']?mysql[-]?username["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MySQL User": regexp.MustCompile(`(?i)["']?mysql[-]?user["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MySQL Root Password": regexp.MustCompile(`(?i)["']?mysql[-]?root[-]?password["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MySQL Password": regexp.MustCompile(`(?i)["']?mysql[-]?password["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MySQL Hostname": regexp.MustCompile(`(?i)["']?mysql[-]?hostname["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MySQL Database": regexp.MustCompile(`(?i)["']?mysql[_-]?database["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - My Secret Env": regexp.MustCompile(`(?i)["']?my[-]?secret[-]?env["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Multi Workspace SID": regexp.MustCompile(`(?i)["']?multi[-]?workspace[-]?sid["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Multi Workflow SID": regexp.MustCompile(`(?i)["']?multi[-]?workflow[-]?sid["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Multi Disconnect SID": regexp.MustCompile(`(?i)["']?multi[-]?disconnect[-]?sid["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Multi Connect SID": regexp.MustCompile(`(?i)["']?multi[-]?connect[-]?sid["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Multi Bob SID": regexp.MustCompile(`(?i)["']?multi[-]?bob[-]?sid["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MinIO Secret Key": regexp.MustCompile(`(?i)["']?minio[-]?secret[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MinIO Access Key": regexp.MustCompile(`(?i)["']?minio[-]?access[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mile Zero Key": regexp.MustCompile(`(?i)["']?mile[-]?zero[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MH Password": regexp.MustCompile(`(?i)["']?mh[_-]?password["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MH API Key": regexp.MustCompile(`(?i)["']?mh[_-]?apikey["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MG Public API Key": regexp.MustCompile(`(?i)["']?mg[-]?public[-]?api[_-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - MG API Key": regexp.MustCompile(`(?i)["']?mg[-]?api[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mapbox Access Token": regexp.MustCompile(`(?i)["']?mapboxaccesstoken["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mapbox AWS Secret Access Key": regexp.MustCompile(`(?i)["']?mapbox[-]?aws[-]?secret[-]?access[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mapbox AWS Access Key ID": regexp.MustCompile(`(?i)["']?mapbox[-]?aws[-]?access[-]?key[-]?id["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mapbox API Token": regexp.MustCompile(`(?i)["']?mapbox[-]?api[-]?token["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mapbox Access Token (Alt)": regexp.MustCompile(`(?i)["']?mapbox[-]?access[-]?token["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Manifest App URL": regexp.MustCompile(`(?i)["']?manifest[-]?app[-]?url["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Manifest App Token": regexp.MustCompile(`(?i)["']?manifest[-]?app[-]?token["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mandrill API Key": regexp.MustCompile(`(?i)["']?mandrill[-]?api[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Management API Access Token": regexp.MustCompile(`(?i)["']?managementapiaccesstoken["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Management Token": regexp.MustCompile(`(?i)["']?management[_-]?token["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Manage Secret": regexp.MustCompile(`(?i)["']?manage[_-]?secret["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Manage Key": regexp.MustCompile(`(?i)["']?manage[_-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Secret API Key": regexp.MustCompile(`(?i)["']?mailgun[-]?secret[-]?api[_-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Public Key": regexp.MustCompile(`(?i)["']?mailgun[-]?pub[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Public API Key": regexp.MustCompile(`(?i)["']?mailgun[_-]?api[_-]?key[_-]?pub["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Private Key": regexp.MustCompile(`(?i)["']?mailgun[-]?priv[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Password": regexp.MustCompile(`(?i)["']?mailgun[_-]?password["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mailgun API Key": regexp.MustCompile(`(?i)["']?mailgun[_-]?apikey["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mailgun API Key (Alternative)": regexp.MustCompile(`(?i)["']?mailgun[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Access Key": regexp.MustCompile(`(?i)["']?mailgun[_-]?api[_-]?key[_-]?access[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Access API Key": regexp.MustCompile(`(?i)["']?mailgun[_-]?api[_-]?key[_-]?access[_-]?api[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp API Key": regexp.MustCompile(`(?i)["']?mailchimp[_-]?apikey["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp API Key (Alternative)": regexp.MustCompile(`(?i)["']?mailchimp[_-]?apikey[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp Access Key": regexp.MustCompile(`(?i)["']?mailchimp[_-]?apikey[_-]?access[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp Access API Key": regexp.MustCompile(`(?i)["']?mailchimp[_-]?apikey[_-]?access[_-]?api[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mail Sender Password": regexp.MustCompile(`(?i)["']?mail[-]?sender[-]?password["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mail Sender Key": regexp.MustCompile(`(?i)["']?mail[-]?sender[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mail Password": regexp.MustCompile(`(?i)["']?mail[_-]?password["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mail API Key": regexp.MustCompile(`(?i)["']?mail[-]?api[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mail Access Key": regexp.MustCompile(`(?i)["']?mail[-]?access[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mail API Key (Alternative)": regexp.MustCompile(`(?i)["']?mail[_-]?apikey["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magic Token": regexp.MustCompile(`(?i)["']?magic[_-]?token["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magic Link Token": regexp.MustCompile(`(?i)["']?magic[-]?link[-]?token["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magento Token": regexp.MustCompile(`(?i)["']?magento[_-]?token["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magento Password": regexp.MustCompile(`(?i)["']?magento[_-]?password["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magento API Key": regexp.MustCompile(`(?i)["']?magento[_-]?apikey["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magento API Key (Alternative)": regexp.MustCompile(`(?i)["']?magento[-]?api[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magic Secret": regexp.MustCompile(`(?i)["']?magic[_-]?secret["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magic Secret Token": regexp.MustCompile(`(?i)["']?magic[-]?secret[-]?token["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magic Secret Key": regexp.MustCompile(`(?i)["']?magic[-]?secret[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magic Access Token": regexp.MustCompile(`(?i)["']?magic[-]?access[-]?token["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magic Access Key": regexp.MustCompile(`(?i)["']?magic[-]?access[-]?key["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Magic API Key": regexp.MustCompile(`(?i)["']?magic[_-]?apikey["']?[^\S
][=:][^\S
]["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Private API Key": regexp.MustCompile(`(?i)["']?mailgun[_-]?api[_-]?key[_-]?priv["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailgun API Key Password": regexp.MustCompile(`(?i)["']?mailgun[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Access Public Key": regexp.MustCompile(`(?i)["']?mailgun[_-]?access[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Access Private Key": regexp.MustCompile(`(?i)["']?mailgun[_-]?access[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailgun Access Token": regexp.MustCompile(`(?i)["']?mailgun[_-]?access[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp Public API Key": regexp.MustCompile(`(?i)["']?mailchimp[_-]?apikey[_-]?pub["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp Private API Key": regexp.MustCompile(`(?i)["']?mailchimp[_-]?apikey[_-]?priv["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp API Key Password": regexp.MustCompile(`(?i)["']?mailchimp[_-]?apikey[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp Access Public Key": regexp.MustCompile(`(?i)["']?mailchimp[_-]?access[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp Access Private Key": regexp.MustCompile(`(?i)["']?mailchimp[_-]?access[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailchimp Access Token": regexp.MustCompile(`(?i)["']?mailchimp[_-]?access[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailer Key": regexp.MustCompile(`(?i)["']?mailer[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailer Token": regexp.MustCompile(`(?i)["']?mailer[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailer Access Token": regexp.MustCompile(`(?i)["']?mailer[_-]?access[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailer Access Key": regexp.MustCompile(`(?i)["']?mailer[_-]?access[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Mailer Access API Key": regexp.MustCompile(`(?i)["']?mailer[_-]?access[_-]?api[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft API Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft API Key (Alt)": regexp.MustCompile(`(?i)["']?microsoft[_-]?api[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft API Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?api[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Access Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?access[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Access Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?access[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Access API Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?access[_-]?api[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Access Public Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?access[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Access Private Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?access[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Access Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?access[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Access Secret Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?access[_-]?secret[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Project Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?project[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account API Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret API Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Client ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?client[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Client Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?client[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key API Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key Auth Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key Public Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key Private Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key Secret Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?secret[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key Secret Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?secret[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Private Key Secret Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?private[_-]?key[_-]?secret[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Public Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?public[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Project ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?project[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Project Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?project[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret Secret ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?secret[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret API Key ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret API Key Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret API Key APIKey": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret API Key Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret API Key Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret API Key Auth Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret API Key Public Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Secret API Key Private Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token API Key ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token API Key Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token API Key APIKey": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token API Key Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token API Key Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token API Key Auth Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token API Key Public Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Token API Key Private Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth API Key ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth API Key Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth API Key APIKey": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth API Key Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth API Key Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth API Key Auth Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth API Key Public Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Service Account Auth API Key Private Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?service[_-]?account[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret API Key ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret API Key Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret API Key APIKey": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret API Key Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret API Key Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret API Key Auth Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret API Key Public Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Secret API Key Private Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?token[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?token[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token API Key ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?token[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token API Key Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?token[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token API Key APIKey": regexp.MustCompile(`(?i)["']?microsoft[_-]?token[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token API Key Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?token[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token API Key Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?token[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token API Key Auth Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token API Key Public Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Token API Key Private Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Auth ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?auth[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Auth Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?auth[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Auth API Key ID": regexp.MustCompile(`(?i)["']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Auth API Key Secret": regexp.MustCompile(`(?i)["']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Auth API Key APIKey": regexp.MustCompile(`(?i)["']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Auth API Key Password": regexp.MustCompile(`(?i)["']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Auth API Key Token": regexp.MustCompile(`(?i)["']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Auth API Key Auth Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Auth API Key Public Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Microsoft Auth API Key Private Key": regexp.MustCompile(`(?i)["']?microsoft[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Use SSH": regexp.MustCompile(`(?i)["']?use[_-]?ssh["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - AWS ELB US-East-1": regexp.MustCompile(`(?i)["']?us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Urban Secret": regexp.MustCompile(`(?i)["']?urban[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Urban Master Secret": regexp.MustCompile(`(?i)["']?urban[_-]?master[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Urban Key": regexp.MustCompile(`(?i)["']?urban[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Unity Serial": regexp.MustCompile(`(?i)["']?unity[_-]?serial["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Unity Password": regexp.MustCompile(`(?i)["']?unity[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter OAuth Access Token": regexp.MustCompile(`(?i)["']?twitteroauthaccesstoken["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter OAuth Access Secret": regexp.MustCompile(`(?i)["']?twitteroauthaccesssecret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Consumer Secret": regexp.MustCompile(`(?i)["']?twitter[_-]?consumer[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Consumer Key": regexp.MustCompile(`(?i)["']?twitter[_-]?consumer[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - VSCE Token": regexp.MustCompile(`(?i)["']?vscetoken["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Visual Recognition API Key": regexp.MustCompile(`(?i)["']?visual[_-]?recognition[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - VirusTotal API Key": regexp.MustCompile(`(?i)["']?virustotal[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - VIP GitHub Deploy Key Password": regexp.MustCompile(`(?i)["']?vip[_-]?github[_-]?deploy[_-]?key[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - VIP GitHub Deploy Key": regexp.MustCompile(`(?i)["']?vip[_-]?github[_-]?deploy[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - VIP GitHub Build Repo Deploy Key": regexp.MustCompile(`(?i)["']?vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Salesforce Password": regexp.MustCompile(`(?i)["']?v[_-]?sfdc[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Salesforce Client Secret": regexp.MustCompile(`(?i)["']?v[_-]?sfdc[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - User Travis": regexp.MustCompile(`(?i)["']?usertravis["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - User Assets Secret Access Key": regexp.MustCompile(`(?i)["']?user[_-]?assets[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - User Assets Access Key ID": regexp.MustCompile(`(?i)["']?user[_-]?assets[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Widget Test Server": regexp.MustCompile(`(?i)["']?widget[_-]?test[_-]?server["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Widget FB Password 3": regexp.MustCompile(`(?i)["']?widget[_-]?fb[_-]?password[_-]?3["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Widget FB Password 2": regexp.MustCompile(`(?i)["']?widget[_-]?fb[_-]?password[_-]?2["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Widget FB Password": regexp.MustCompile(`(?i)["']?widget[_-]?fb[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Widget Basic Password 5": regexp.MustCompile(`(?i)["']?widget[_-]?basic[_-]?password[_-]?5["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Widget Basic Password 4": regexp.MustCompile(`(?i)["']?widget[_-]?basic[_-]?password[_-]?4["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Widget Basic Password 3": regexp.MustCompile(`(?i)["']?widget[_-]?basic[_-]?password[_-]?3["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Widget Basic Password 2": regexp.MustCompile(`(?i)["']?widget[_-]?basic[_-]?password[_-]?2["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Widget Basic Password": regexp.MustCompile(`(?i)["']?widget[_-]?basic[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Watson Password": regexp.MustCompile(`(?i)["']?watson[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Watson Device Password": regexp.MustCompile(`(?i)["']?watson[_-]?device[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Watson Conversation Password": regexp.MustCompile(`(?i)["']?watson[_-]?conversation[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - WakaTime API Key": regexp.MustCompile(`(?i)["']?wakatime[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Sonar Token": regexp.MustCompile(`(?i)["']?sonar[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Sonar Project Key": regexp.MustCompile(`(?i)["']?sonar[_-]?project[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Sonar Organization Key": regexp.MustCompile(`(?i)["']?sonar[_-]?organization[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Socrata Password": regexp.MustCompile(`(?i)["']?socrata[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Socrata App Token": regexp.MustCompile(`(?i)["']?socrata[_-]?app[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Snyk Token": regexp.MustCompile(`(?i)["']?snyk[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Snyk API Token": regexp.MustCompile(`(?i)["']?snyk[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - WPJM PHPUnit Google Geocode API Key": regexp.MustCompile(`(?i)["']?wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - WordPress DB User": regexp.MustCompile(`(?i)["']?wordpress[_-]?db[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - WordPress DB Password": regexp.MustCompile(`(?i)["']?wordpress[_-]?db[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - WinCert Password": regexp.MustCompile(`(?i)["']?wincert[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Spotify API Client Secret": regexp.MustCompile(`(?i)["']?spotify[_-]?api[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Spotify API Access Token": regexp.MustCompile(`(?i)["']?spotify[_-]?api[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Spaces Secret Access Key": regexp.MustCompile(`(?i)["']?spaces[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Spaces Access Key ID": regexp.MustCompile(`(?i)["']?spaces[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - SoundCloud Password": regexp.MustCompile(`(?i)["']?soundcloud[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - SoundCloud Client Secret": regexp.MustCompile(`(?i)["']?soundcloud[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Sonatype Password": regexp.MustCompile(`(?i)["']?sonatype[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Sonatype Token User": regexp.MustCompile(`(?i)["']?sonatype[_-]?token[_-]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Sonatype Token Password": regexp.MustCompile(`(?i)["']?sonatype[_-]?token[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Sonatype Pass": regexp.MustCompile(`(?i)["']?sonatype[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Sonatype Nexus Password": regexp.MustCompile(`(?i)["']?sonatype[_-]?nexus[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Sonatype GPG Passphrase": regexp.MustCompile(`(?i)["']?sonatype[_-]?gpg[_-]?passphrase["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Sonatype GPG Key Name": regexp.MustCompile(`(?i)["']?sonatype[_-]?gpg[_-]?key[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Starship Auth Token": regexp.MustCompile(`(?i)["']?starship[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Starship Account SID": regexp.MustCompile(`(?i)["']?starship[_-]?account[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Star Test Secret Access Key": regexp.MustCompile(`(?i)["']?star[_-]?test[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Star Test Location": regexp.MustCompile(`(?i)["']?star[_-]?test[_-]?location["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Star Test Bucket": regexp.MustCompile(`(?i)["']?star[_-]?test[_-]?bucket["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Star Test AWS Access Key ID": regexp.MustCompile(`(?i)["']?star[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Staging Base URL Runscope": regexp.MustCompile(`(?i)["']?staging[_-]?base[_-]?url[_-]?runscope["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - SSMTP Config": regexp.MustCompile(`(?i)["']?ssmtp[_-]?config["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - SSHPass": regexp.MustCompile(`(?i)["']?sshpass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - SrcClr API Token": regexp.MustCompile(`(?i)["']?srcclr[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Square Reader SDK Repository Password": regexp.MustCompile(`(?i)["']?square[_-]?reader[_-]?sdk[_-]?repository[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - SQS Secret Key": regexp.MustCompile(`(?i)["']?sqssecretkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - SQS Access Key": regexp.MustCompile(`(?i)["']?sqsaccesskey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Spring Mail Password": regexp.MustCompile(`(?i)["']?spring[_-]?mail[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Tester Keys Password": regexp.MustCompile(`(?i)["']?tester[_-]?keys[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Test Test": regexp.MustCompile(`(?i)["']?test[_-]?test["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Test GitHub Token": regexp.MustCompile(`(?i)["']?test[_-]?github[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Tesco API Key": regexp.MustCompile(`(?i)["']?tesco[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - SVN Password": regexp.MustCompile(`(?i)["']?svn[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Surge Token": regexp.MustCompile(`(?i)["']?surge[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Surge Login": regexp.MustCompile(`(?i)["']?surge[_-]?login["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Stripe Public Key": regexp.MustCompile(`(?i)["']?stripe[_-]?public["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Stripe Private Key": regexp.MustCompile(`(?i)["']?stripe[_-]?private["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Stripe Secret Key": regexp.MustCompile(`(?i)["']?strip[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Stripe Publishable Key": regexp.MustCompile(`(?i)["']?strip[_-]?publishable[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Stormpath API Key Secret": regexp.MustCompile(`(?i)["']?stormpath[_-]?api[_-]?key[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Stormpath API Key ID": regexp.MustCompile(`(?i)["']?stormpath[_-]?api[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Secret ID": regexp.MustCompile(`(?i)["']?linkedin[_-]?secret[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Secret Secret": regexp.MustCompile(`(?i)["']?linkedin[_-]?secret[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Secret API Key ID": regexp.MustCompile(`(?i)["']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Secret API Key Secret": regexp.MustCompile(`(?i)["']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Secret API Key Apikey": regexp.MustCompile(`(?i)["']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Secret API Key Password": regexp.MustCompile(`(?i)["']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Secret API Key Token": regexp.MustCompile(`(?i)["']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Secret API Key Auth Key": regexp.MustCompile(`(?i)["']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Secret API Key Pub Key": regexp.MustCompile(`(?i)["']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Secret API Key Priv Key": regexp.MustCompile(`(?i)["']?linkedin[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token ID": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token Secret": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token API Key ID": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token API Key Secret": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token API Key Apikey": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token API Key Password": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token API Key Token": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token API Key Auth Key": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token API Key Pub Key": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token API Key Priv Key": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Auth ID": regexp.MustCompile(`(?i)["']?linkedin[_-]?auth[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Auth Secret": regexp.MustCompile(`(?i)["']?linkedin[_-]?auth[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Auth API Key ID": regexp.MustCompile(`(?i)["']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Auth API Key Secret": regexp.MustCompile(`(?i)["']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Auth API Key Apikey": regexp.MustCompile(`(?i)["']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Auth API Key Password": regexp.MustCompile(`(?i)["']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Auth API Key Token": regexp.MustCompile(`(?i)["']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Auth API Key Auth Key": regexp.MustCompile(`(?i)["']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Auth API Key Pub Key": regexp.MustCompile(`(?i)["']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Auth API Key Priv Key": regexp.MustCompile(`(?i)["']?linkedin[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - LinkedIn Token Auth Token": regexp.MustCompile(`(?i)["']?linkedin[_-]?token[_-]?auth[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Secret ID": regexp.MustCompile(`(?i)["']?azure[_-]?secret[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Secret Secret": regexp.MustCompile(`(?i)["']?azure[_-]?secret[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Secret API Key ID": regexp.MustCompile(`(?i)["']?azure[_-]?secret[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Secret API Key Secret": regexp.MustCompile(`(?i)["']?azure[_-]?secret[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Secret API Key Apikey": regexp.MustCompile(`(?i)["']?azure[_-]?secret[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Secret API Key Password": regexp.MustCompile(`(?i)["']?azure[_-]?secret[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Secret API Key Token": regexp.MustCompile(`(?i)["']?azure[_-]?secret[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Secret API Key Auth Key": regexp.MustCompile(`(?i)["']?azure[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Secret API Key Pub Key": regexp.MustCompile(`(?i)["']?azure[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Secret API Key Priv Key": regexp.MustCompile(`(?i)["']?azure[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Token ID": regexp.MustCompile(`(?i)["']?azure[_-]?token[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Token Secret": regexp.MustCompile(`(?i)["']?azure[_-]?token[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Token API Key ID": regexp.MustCompile(`(?i)["']?azure[_-]?token[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Token API Key Secret": regexp.MustCompile(`(?i)["']?azure[_-]?token[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Token API Key Apikey": regexp.MustCompile(`(?i)["']?azure[_-]?token[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Token API Key Password": regexp.MustCompile(`(?i)["']?azure[_-]?token[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Token API Key Token": regexp.MustCompile(`(?i)["']?azure[_-]?token[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Token API Key Auth Key": regexp.MustCompile(`(?i)["']?azure[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Token API Key Pub Key": regexp.MustCompile(`(?i)["']?azure[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Token API Key Priv Key": regexp.MustCompile(`(?i)["']?azure[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Auth ID": regexp.MustCompile(`(?i)["']?azure[_-]?auth[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Auth Secret": regexp.MustCompile(`(?i)["']?azure[_-]?auth[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Auth API Key ID": regexp.MustCompile(`(?i)["']?azure[_-]?auth[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Auth API Key Secret": regexp.MustCompile(`(?i)["']?azure[_-]?auth[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Auth API Key Apikey": regexp.MustCompile(`(?i)["']?azure[_-]?auth[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Auth API Key Password": regexp.MustCompile(`(?i)["']?azure[_-]?auth[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Auth API Key Token": regexp.MustCompile(`(?i)["']?azure[_-]?auth[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Auth API Key Auth Key": regexp.MustCompile(`(?i)["']?azure[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Auth API Key Pub Key": regexp.MustCompile(`(?i)["']?azure[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Azure Auth API Key Priv Key": regexp.MustCompile(`(?i)["']?azure[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twilio Token": regexp.MustCompile(`(?i)["']?twilio[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twilio SID": regexp.MustCompile(`(?i)["']?twilio[_-]?sid["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twilio Configuration SID": regexp.MustCompile(`(?i)["']?twilio[_-]?configuration[_-]?sid["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twilio Chat Account API Service": regexp.MustCompile(`(?i)["']?twilio[_-]?chat[_-]?account[_-]?api[_-]?service["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twilio API Secret": regexp.MustCompile(`(?i)["']?twilio[_-]?api[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twilio API Key": regexp.MustCompile(`(?i)["']?twilio[_-]?api[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Trex Okta Client Token": regexp.MustCompile(`(?i)["']?trex[_-]?okta[_-]?client[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Trex Client Token": regexp.MustCompile(`(?i)["']?trex[_-]?client[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Travis Token": regexp.MustCompile(`(?i)["']?travis[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Travis Secure Env Vars": regexp.MustCompile(`(?i)["']?travis[_-]?secure[_-]?env[_-]?vars["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Travis Pull Request": regexp.MustCompile(`(?i)["']?travis[_-]?pull[_-]?request["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Travis GH Token": regexp.MustCompile(`(?i)["']?travis[_-]?gh[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Travis E2E Token": regexp.MustCompile(`(?i)["']?travis[_-]?e2e[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Travis Com Token": regexp.MustCompile(`(?i)["']?travis[_-]?com[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Travis Branch": regexp.MustCompile(`(?i)["']?travis[_-]?branch["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Travis API Token": regexp.MustCompile(`(?i)["']?travis[_-]?api[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Travis Access Token": regexp.MustCompile(`(?i)["']?travis[_-]?access[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Token Core Java": regexp.MustCompile(`(?i)["']?token[_-]?core[_-]?java["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Thera OSS Access Key": regexp.MustCompile(`(?i)["']?thera[_-]?oss[_-]?access[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret Key": regexp.MustCompile(`(?i)["']?secretkey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret Access Key": regexp.MustCompile(`(?i)["']?secretaccesskey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret Key Base": regexp.MustCompile(`(?i)["']?secret[_-]?key[_-]?base["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 9": regexp.MustCompile(`(?i)["']?secret[_-]?9["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 8": regexp.MustCompile(`(?i)["']?secret[_-]?8["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 7": regexp.MustCompile(`(?i)["']?secret[_-]?7["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 6": regexp.MustCompile(`(?i)["']?secret[_-]?6["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 5": regexp.MustCompile(`(?i)["']?secret[_-]?5["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 4": regexp.MustCompile(`(?i)["']?secret[_-]?4["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 3": regexp.MustCompile(`(?i)["']?secret[_-]?3["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 2": regexp.MustCompile(`(?i)["']?secret[_-]?2["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 11": regexp.MustCompile(`(?i)["']?secret[_-]?11["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 10": regexp.MustCompile(`(?i)["']?secret[_-]?10["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 1": regexp.MustCompile(`(?i)["']?secret[_-]?1["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Secret 0": regexp.MustCompile(`(?i)["']?secret[_-]?0["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SDR Token": regexp.MustCompile(`(?i)["']?sdr[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Scrutinizer Token": regexp.MustCompile(`(?i)["']?scrutinizer[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Sauce Access Key": regexp.MustCompile(`(?i)["']?sauce[_-]?access[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Sandbox AWS Secret Access Key": regexp.MustCompile(`(?i)["']?sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Sandbox AWS Access Key ID": regexp.MustCompile(`(?i)["']?sandbox[_-]?aws[_-]?access[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twine Password": regexp.MustCompile(`(?i)["']?twine[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Sentry Key": regexp.MustCompile(`(?i)["']?sentry[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Sentry Secret": regexp.MustCompile(`(?i)["']?sentry[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Sentry Endpoint": regexp.MustCompile(`(?i)["']?sentry[_-]?endpoint["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Sentry Default Org": regexp.MustCompile(`(?i)["']?sentry[_-]?default[_-]?org["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Sentry Auth Token": regexp.MustCompile(`(?i)["']?sentry[_-]?auth[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SendWithUs Key": regexp.MustCompile(`(?i)["']?sendwithus[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SendGrid Username": regexp.MustCompile(`(?i)["']?sendgrid[_-]?username["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SendGrid User": regexp.MustCompile(`(?i)["']?sendgrid[_-]?user["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SendGrid Password": regexp.MustCompile(`(?i)["']?sendgrid[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SendGrid Key": regexp.MustCompile(`(?i)["']?sendgrid[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SendGrid API Key": regexp.MustCompile(`(?i)["']?sendgrid[_-]?api[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SendGrid Generic": regexp.MustCompile(`(?i)["']?sendgrid["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Selion Selenium Host": regexp.MustCompile(`(?i)["']?selion[_-]?selenium[_-]?host["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Selion Log Level Dev": regexp.MustCompile(`(?i)["']?selion[_-]?log[_-]?level[_-]?dev["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Segment API Key": regexp.MustCompile(`(?i)["']?segment[_-]?api[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Snoowrap Refresh Token": regexp.MustCompile(`(?i)["']?snoowrap[_-]?refresh[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Snoowrap Password": regexp.MustCompile(`(?i)["']?snoowrap[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Snoowrap Client Secret": regexp.MustCompile(`(?i)["']?snoowrap[_-]?client[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Slate User Email": regexp.MustCompile(`(?i)["']?slate[_-]?user[_-]?email["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Slash Developer Space Key": regexp.MustCompile(`(?i)["']?slash[_-]?developer[_-]?space[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Slash Developer Space": regexp.MustCompile(`(?i)["']?slash[_-]?developer[_-]?space["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Signing Key SID": regexp.MustCompile(`(?i)["']?signing[_-]?key[_-]?sid["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Signing Key Secret": regexp.MustCompile(`(?i)["']?signing[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Signing Key Password": regexp.MustCompile(`(?i)["']?signing[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Signing Key": regexp.MustCompile(`(?i)["']?signing[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Set Secret Key": regexp.MustCompile(`(?i)["']?setsecretkey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Set DST Secret Key": regexp.MustCompile(`(?i)["']?setdstsecretkey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Set DST Access Key": regexp.MustCompile(`(?i)["']?setdstaccesskey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SES Secret Key": regexp.MustCompile(`(?i)["']?ses[_-]?secret[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SES Access Key": regexp.MustCompile(`(?i)["']?ses[_-]?access[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Service Account Secret": regexp.MustCompile(`(?i)["']?service[_-]?account[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Postgres": regexp.MustCompile(`(?i)["']?password[-_]?postgres["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Private": regexp.MustCompile(`(?i)["']?password[-_]?private["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Prod": regexp.MustCompile(`(?i)["']?password[-_]?prod["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Preview": regexp.MustCompile(`(?i)["']?password[-_]?preview["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password PyPI": regexp.MustCompile(`(?i)["']?password[-_]?pypi["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Publish": regexp.MustCompile(`(?i)["']?password[-_]?publish["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password QLD": regexp.MustCompile(`(?i)["']?password[-_]?qld["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Pub": regexp.MustCompile(`(?i)["']?password[-_]?pub["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Priv": regexp.MustCompile(`(?i)["']?password[-_]?priv["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Prod Private": regexp.MustCompile(`(?i)["']?password[-_]?prod[-_]?private["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password PR": regexp.MustCompile(`(?i)["']?password[-_]?pr["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Preprod": regexp.MustCompile(`(?i)["']?password[-_]?preprod["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Preprod Secret": regexp.MustCompile(`(?i)["']?password[-_]?preprod[-_]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password PR Live": regexp.MustCompile(`(?i)["']?password[-_]?pr[-_]?live["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password P4": regexp.MustCompile(`(?i)["']?password[-_]?p4["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password P2": regexp.MustCompile(`(?i)["']?password[-_]?p2["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password P1": regexp.MustCompile(`(?i)["']?password[-_]?p1["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password P Mail": regexp.MustCompile(`(?i)["']?password[-_]?p[-_]?mail["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password P": regexp.MustCompile(`(?i)["']?password[-_]?p["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password OS AeroGear": regexp.MustCompile(`(?i)["']?password[-_]?os[-_]?aerogear["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password OpenSource": regexp.MustCompile(`(?i)["']?password[-_]?opensource["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password OAuth": regexp.MustCompile(`(?i)["']?password[-_]?oauth["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password OAuth Token": regexp.MustCompile(`(?i)["']?password[-_]?oauth[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password O": regexp.MustCompile(`(?i)["']?password[-_]?o["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password MyWeb": regexp.MustCompile(`(?i)["']?password[-_]?myweb["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password MyGit": regexp.MustCompile(`(?i)["']?password[-_]?mygit["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password My GitHub": regexp.MustCompile(`(?i)["']?password[-_]?my[-_]?github["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password My Git": regexp.MustCompile(`(?i)["']?password[-_]?my[-_]?git["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Migrations": regexp.MustCompile(`(?i)["']?password[-_]?migrations["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password MC4": regexp.MustCompile(`(?i)["']?password[-_]?mc4["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Key": regexp.MustCompile(`(?i)["']?password[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password JWT": regexp.MustCompile(`(?i)["']?password[-_]?jwt["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Jira": regexp.MustCompile(`(?i)["']?password[-_]?jira["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - PyPI Password": regexp.MustCompile(`(?i)["']?pypi[-_]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Pushover Token": regexp.MustCompile(`(?i)["']?pushover[-_]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Pushover User": regexp.MustCompile(`(?i)["']?pushover[-_]?user["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Pusher App Secret": regexp.MustCompile(`(?i)["']?pusher[-_]?app[-_]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - PubNub Subscribe Key": regexp.MustCompile(`(?i)["']?pubnub[-_]?subscribe[-_]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - PubNub Secret Key": regexp.MustCompile(`(?i)["']?pubnub[-_]?secret[-_]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - PubNub Publish Key": regexp.MustCompile(`(?i)["']?pubnub[-_]?publish[-_]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - PubNub Cipher Key": regexp.MustCompile(`(?i)["']?pubnub[-_]?cipher[-_]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - PubNub Auth Key": regexp.MustCompile(`(?i)["']?pubnub[-_]?auth[-_]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Prometheus Token": regexp.MustCompile(`(?i)["']?prometheus[-_]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Private Key Token": regexp.MustCompile(`(?i)["']?private[-_]?key[-_]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Prismic Token": regexp.MustCompile(`(?i)["']?prismic[-_]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Private Key ID": regexp.MustCompile(`(?i)["']?private[-_]?key[-_]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Project Key": regexp.MustCompile(`(?i)["']?project[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Prod Deploy Key": regexp.MustCompile(`(?i)["']?prod[-_]?deploy[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Private Key": regexp.MustCompile(`(?i)["']?private[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Pivotal Tracker Token": regexp.MustCompile(`(?i)["']?pivotal[-_]?tracker[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Personal Access Token": regexp.MustCompile(`(?i)["']?personal[-_]?access[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Token": regexp.MustCompile(`(?i)["']?password[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - PayPal Client Secret": regexp.MustCompile(`(?i)["']?paypal[-_]?client[-_]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - PayPal Client ID": regexp.MustCompile(`(?i)["']?paypal[-_]?client[-_]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Path To File": regexp.MustCompile(`(?i)["']?path[-_]?to[-_]?file["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Passwd S3 Access Key": regexp.MustCompile(`(?i)["']?passwd[-_]?s3[-_]?access[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Passwd S3 Secret Key": regexp.MustCompile(`(?i)["']?passwd[-_]?s3[-_]?secret[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password To Jenkins": regexp.MustCompile(`(?i)["']?password[-_]?to[-_]?jenkins["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password To File": regexp.MustCompile(`(?i)["']?password[-_]?to[-_]?file["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password To Azure File": regexp.MustCompile(`(?i)["']?password[-_]?to[-_]?azure[-_]?file["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Test": regexp.MustCompile(`(?i)["']?password[-_]?test["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Storj": regexp.MustCompile(`(?i)["']?password[-_]?storj["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Staging": regexp.MustCompile(`(?i)["']?password[-_]?staging["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Stage": regexp.MustCompile(`(?i)["']?password[-_]?stage["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Slack": regexp.MustCompile(`(?i)["']?password[-_]?slack["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Secret": regexp.MustCompile(`(?i)["']?password[-_]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password S3": regexp.MustCompile(`(?i)["']?password[-_]?s3["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password Repo": regexp.MustCompile(`(?i)["']?password[-_]?repo["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Password RDS": regexp.MustCompile(`(?i)["']?password[-_]?rds["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Repo Token": regexp.MustCompile(`(?i)["']?repotoken["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Reporting WebDav URL": regexp.MustCompile(`(?i)["']?reporting[-_]?webdav[-_]?url["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Reporting WebDav Password": regexp.MustCompile(`(?i)["']?reporting[-_]?webdav[-_]?pwd["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Release Token": regexp.MustCompile(`(?i)["']?release[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Release GitHub Token": regexp.MustCompile(`(?i)["']?release[-_]?gh[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Registry Secure": regexp.MustCompile(`(?i)["']?registry[-_]?secure["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Registry Password": regexp.MustCompile(`(?i)["']?registry[-_]?pass["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Refresh Token": regexp.MustCompile(`(?i)["']?refresh[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - RedisCloud URL": regexp.MustCompile(`(?i)["']?rediscloud[-_]?url["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Redis Stunnel URLs": regexp.MustCompile(`(?i)["']?redis[-_]?stunnel[-_]?urls["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Randr Music API Access Token": regexp.MustCompile(`(?i)["']?randrmusicapiaccesstoken["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - RabbitMQ Password": regexp.MustCompile(`(?i)["']?rabbitmq[-_]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Quip Token": regexp.MustCompile(`(?i)["']?quip[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Qiita Token": regexp.MustCompile(`(?i)["']?qiita[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Salesforce Bulk Test Security Token": regexp.MustCompile(`(?i)["']?salesforce[-_]?bulk[-_]?test[-_]?security[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Salesforce Bulk Test Password": regexp.MustCompile(`(?i)["']?salesforce[-_]?bulk[-_]?test[-_]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SACloud API": regexp.MustCompile(`(?i)["']?sacloud[-_]?api["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SACloud Access Token Secret": regexp.MustCompile(`(?i)["']?sacloud[-_]?access[-_]?token[-_]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - SACloud Access Token": regexp.MustCompile(`(?i)["']?sacloud[-_]?access[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 User Secret": regexp.MustCompile(`(?i)["']?s3[-_]?user[-_]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 Secret Key": regexp.MustCompile(`(?i)["']?s3[-_]?secret[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 Secret Assets": regexp.MustCompile(`(?i)["']?s3[-_]?secret[-_]?assets["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 Secret App Logs": regexp.MustCompile(`(?i)["']?s3[-_]?secret[-_]?app[-_]?logs["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 Key Assets": regexp.MustCompile(`(?i)["']?s3[-_]?key[-_]?assets["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 Key App Logs": regexp.MustCompile(`(?i)["']?s3[-_]?key[-_]?app[-_]?logs["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 Key": regexp.MustCompile(`(?i)["']?s3[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 External Amazonaws": regexp.MustCompile(`(?i)["']?s3[-_]?external[-_]?3[-_]?amazonaws[-_]?com["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 Bucket Name Assets": regexp.MustCompile(`(?i)["']?s3[-_]?bucket[-_]?name[-_]?assets["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 Bucket Name App Logs": regexp.MustCompile(`(?i)["']?s3[-_]?bucket[-_]?name[-_]?app[-_]?logs["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 Access Key ID": regexp.MustCompile(`(?i)["']?s3[-_]?access[-_]?key[-_]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - S3 Access Key": regexp.MustCompile(`(?i)["']?s3[-_]?access[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Rubygems Auth Token": regexp.MustCompile(`(?i)["']?rubygems[-_]?auth[-_]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - RTD Store Pass": regexp.MustCompile(`(?i)["']?rtd[-_]?store[-_]?pass["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - RTD Key Pass": regexp.MustCompile(`(?i)["']?rtd[-_]?key[-_]?pass["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Route53 Access Key ID": regexp.MustCompile(`(?i)["']?route53[-_]?access[-_]?key[-_]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Ropsten Private Key": regexp.MustCompile(`(?i)["']?ropsten[-_]?private[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Rinkeby Private Key": regexp.MustCompile(`(?i)["']?rinkeby[-_]?private[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - REST API Key": regexp.MustCompile(`(?i)["']?rest[-_]?api[-_]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube Secret ID": regexp.MustCompile(`(?i)["']?youtube[_-]?secret[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube Secret Secret": regexp.MustCompile(`(?i)["']?youtube[_-]?secret[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube API Key ID": regexp.MustCompile(`(?i)["']?youtube[_-]?secret[_-]?api[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube API Key Secret": regexp.MustCompile(`(?i)["']?youtube[_-]?secret[_-]?api[_-]?key[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube API Key Apikey": regexp.MustCompile(`(?i)["']?youtube[_-]?secret[_-]?api[_-]?key[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube API Key Password": regexp.MustCompile(`(?i)["']?youtube[_-]?secret[_-]?api[_-]?key[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube API Key Token": regexp.MustCompile(`(?i)["']?youtube[_-]?secret[_-]?api[_-]?key[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube API Key Auth Key": regexp.MustCompile(`(?i)["']?youtube[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube API Key Public Key": regexp.MustCompile(`(?i)["']?youtube[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube API Key Private Key": regexp.MustCompile(`(?i)["']?youtube[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube Token ID": regexp.MustCompile(`(?i)["']?youtube[_-]?token[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube Token Secret": regexp.MustCompile(`(?i)["']?youtube[_-]?token[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube Token API Key ID": regexp.MustCompile(`(?i)["']?youtube[_-]?token[_-]?api[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube Token API Key Secret": regexp.MustCompile(`(?i)["']?youtube[_-]?token[_-]?api[_-]?key[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - YouTube Token API Key Apikey": regexp.MustCompile(`(?i)["']?youtube[_-]?token[_-]?api[_-]?key[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Secret ID": regexp.MustCompile(`(?i)["']?twitter[_-]?secret[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Secret Secret": regexp.MustCompile(`(?i)["']?twitter[_-]?secret[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Secret API Key ID": regexp.MustCompile(`(?i)["']?twitter[_-]?secret[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Secret API Key Secret": regexp.MustCompile(`(?i)["']?twitter[_-]?secret[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Secret API Key Apikey": regexp.MustCompile(`(?i)["']?twitter[_-]?secret[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Secret API Key Password": regexp.MustCompile(`(?i)["']?twitter[_-]?secret[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Secret API Key Token": regexp.MustCompile(`(?i)["']?twitter[_-]?secret[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Secret API Key Auth Key": regexp.MustCompile(`(?i)["']?twitter[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Secret API Key Pub Key": regexp.MustCompile(`(?i)["']?twitter[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Secret API Key Priv Key": regexp.MustCompile(`(?i)["']?twitter[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token ID": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token Secret": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token API Key ID": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token API Key Secret": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token API Key Apikey": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token API Key Password": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token API Key Token": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token API Key Auth Key": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token API Key Pub Key": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token API Key Priv Key": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth ID": regexp.MustCompile(`(?i)["']?twitter[_-]?auth[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth Secret": regexp.MustCompile(`(?i)["']?twitter[_-]?auth[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth API Key ID": regexp.MustCompile(`(?i)["']?twitter[_-]?auth[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth API Key Secret": regexp.MustCompile(`(?i)["']?twitter[_-]?auth[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth API Key Apikey": regexp.MustCompile(`(?i)["']?twitter[_-]?auth[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth API Key Password": regexp.MustCompile(`(?i)["']?twitter[_-]?auth[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth API Key Token": regexp.MustCompile(`(?i)["']?twitter[_-]?auth[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth API Key Auth Key": regexp.MustCompile(`(?i)["']?twitter[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth API Key Pub Key": regexp.MustCompile(`(?i)["']?twitter[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Auth API Key Priv Key": regexp.MustCompile(`(?i)["']?twitter[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Twitter Token Auth Token": regexp.MustCompile(`(?i)["']?twitter[_-]?token[_-]?auth[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Secret ID": regexp.MustCompile(`(?i)["']?gitlab[_-]?secret[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Secret Secret": regexp.MustCompile(`(?i)["']?gitlab[_-]?secret[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Secret API Key ID": regexp.MustCompile(`(?i)["']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Secret API Key Secret": regexp.MustCompile(`(?i)["']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Secret API Key Apikey": regexp.MustCompile(`(?i)["']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Secret API Key Password": regexp.MustCompile(`(?i)["']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Secret API Key Token": regexp.MustCompile(`(?i)["']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Secret API Key Auth Key": regexp.MustCompile(`(?i)["']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Secret API Key Pub Key": regexp.MustCompile(`(?i)["']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Secret API Key Priv Key": regexp.MustCompile(`(?i)["']?gitlab[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token ID": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token Secret": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token API Key ID": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token API Key Secret": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token API Key Apikey": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token API Key Password": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token API Key Token": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token API Key Auth Key": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token API Key Pub Key": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token API Key Priv Key": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Auth ID": regexp.MustCompile(`(?i)["']?gitlab[_-]?auth[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Auth Secret": regexp.MustCompile(`(?i)["']?gitlab[_-]?auth[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Auth API Key ID": regexp.MustCompile(`(?i)["']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?id["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Auth API Key Secret": regexp.MustCompile(`(?i)["']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?secret["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Auth API Key Apikey": regexp.MustCompile(`(?i)["']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?apikey["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Auth API Key Password": regexp.MustCompile(`(?i)["']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?password["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Auth API Key Token": regexp.MustCompile(`(?i)["']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Auth API Key Auth Key": regexp.MustCompile(`(?i)["']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Auth API Key Pub Key": regexp.MustCompile(`(?i)["']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Auth API Key Priv Key": regexp.MustCompile(`(?i)["']?gitlab[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - GitLab Token Auth Token": regexp.MustCompile(`(?i)["']?gitlab[_-]?token[_-]?auth[_-]?token["']?[^\S
]*[=:][^\S
]*["']?[\w-]+["']?`),
	"Possible Leak - Facebook Secret": regexp.MustCompile(`(?i)["']?facebook[_-]?secret[_-]?(?:id|password|secret|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)["']?[^\S\r\n]*[=:][^\S\r\n]*["']?([\w-]+)["']?`),
	"Possible Leak - Facebook Token": regexp.MustCompile(`(?i)["']?facebook[_-]?token[_-]?(?:id|password|secret|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)["']?[^\S\r\n]*[=:][^\S\r\n]*["']?([\w-]+)["']?`),
	"Possible Leak - Facebook Auth": regexp.MustCompile(`(?i)["']?facebook[_-]?auth[_-]?(?:id|password|secret|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)["']?[^\S\r\n]*[=:][^\S\r\n]*["']?([\w-]+)["']?`),
	"Possible Leak - Facebook API Key": regexp.MustCompile(`(?i)["']?facebook[_-]?api[_-]?key[_-]?(?:id|password|secret|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)["']?[^\S\r\n]*[=:][^\S\r\n]*["']?([\w-]+)["']?`),
	"Possible Leak - AWS Secret ID": regexp.MustCompile(`(?i)["']?aws[_-]?secret[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?([\w-]+)["']?`),
	"Possible Leak - AWS API Key": regexp.MustCompile(`(?i)["']?aws[_-]?api[_-]?key[_-]?(?:id|secret|apikey|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)["']?[^\S\r\n]*[=:][^\S\r\n]*["']?([\w-]+)["']?`),
	"Possible Leak - AWS Token": regexp.MustCompile(`(?i)["']?aws[_-]?token[_-]?(?:id|secret|api[_-]?key[_-]?(?:id|secret|apikey|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)|auth[_-]?token)["']?[^\S\r\n]*[=:][^\S\r\n]*["']?([\w-]+)["']?`),
	"Possible Leak - AWS Auth Key": regexp.MustCompile(`(?i)["']?aws[_-]?auth[_-]?(?:id|secret|api[_-]?key[_-]?(?:id|secret|apikey|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key))?["']?[^\S\r\n]*[=:][^\S\r\n]*["']?([\w-]+)["']?`),
	"Amazon_Secret_ID": regexp.MustCompile(`(?i)["']?amazon[_-]?secret[_-]?id["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Secret_Secret": regexp.MustCompile(`(?i)["']?amazon[_-]?secret[_-]?secret["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_API_Key_ID": regexp.MustCompile(`(?i)["']?amazon[_-]?secret[_-]?api[_-]?key[_-]?id["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_API_Key_Secret": regexp.MustCompile(`(?i)["']?amazon[_-]?secret[_-]?api[_-]?key[_-]?secret["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_API_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?secret[_-]?api[_-]?key[_-]?apikey["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_API_Key_Password": regexp.MustCompile(`(?i)["']?amazon[_-]?secret[_-]?api[_-]?key[_-]?password["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_API_Key_Token": regexp.MustCompile(`(?i)["']?amazon[_-]?secret[_-]?api[_-]?key[_-]?token["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_API_Auth_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?secret[_-]?api[_-]?key[_-]?auth[_-]?key["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Public_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?secret[_-]?api[_-]?key[_-]?pub[_-]?key["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Private_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?secret[_-]?api[_-]?key[_-]?priv[_-]?key["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Token_ID": regexp.MustCompile(`(?i)["']?amazon[_-]?token[_-]?id["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Token_Secret": regexp.MustCompile(`(?i)["']?amazon[_-]?token[_-]?secret["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Token_API_Key_ID": regexp.MustCompile(`(?i)["']?amazon[_-]?token[_-]?api[_-]?key[_-]?id["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Token_API_Key_Secret": regexp.MustCompile(`(?i)["']?amazon[_-]?token[_-]?api[_-]?key[_-]?secret["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Token_API_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?token[_-]?api[_-]?key[_-]?apikey["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Token_API_Key_Password": regexp.MustCompile(`(?i)["']?amazon[_-]?token[_-]?api[_-]?key[_-]?password["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Token_API_Key_Token": regexp.MustCompile(`(?i)["']?amazon[_-]?token[_-]?api[_-]?key[_-]?token["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Token_API_Auth_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?token[_-]?api[_-]?key[_-]?auth[_-]?key["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Token_Public_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?token[_-]?api[_-]?key[_-]?pub[_-]?key["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Token_Private_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?token[_-]?api[_-]?key[_-]?priv[_-]?key["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Auth_ID": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?id["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Auth_Secret": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?secret["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Auth_API_Key_ID": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?api[_-]?key[_-]?id["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Auth_API_Key_Secret": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?api[_-]?key[_-]?secret["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Auth_API_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?api[_-]?key[_-]?apikey["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Auth_API_Key_Password": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?api[_-]?key[_-]?password["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Auth_API_Key_Token": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?api[_-]?key[_-]?token["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Auth_API_Auth_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?api[_-]?key[_-]?auth[_-]?key["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Auth_Public_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?api[_-]?key[_-]?pub[_-]?key["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Amazon_Auth_Private_Key": regexp.MustCompile(`(?i)["']?amazon[_-]?auth[_-]?api[_-]?key[_-]?priv[_-]?key["']?\s*[=:]\s*["']?[\w-]+["']?`),
	"Possible Leak - google secrets": regexp.MustCompile(`(?i)["']?(google[_-]?(secret|token|auth)?[_-]?(api[_-]?)?key[_-]?(id|secret|apikey|password|token|auth[_-]?key|pub[_-]?key|priv[_-]?key)?)["']?\s*[=:]\s*["']?([\w-]+)["']?`),
	"Possible Leak - Flask Secret Key": regexp.MustCompile(`(?i)["']?flask[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Firefox Secret": regexp.MustCompile(`(?i)["']?firefox[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Firebase Token": regexp.MustCompile(`(?i)["']?firebase[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Firebase Project Develop": regexp.MustCompile(`(?i)["']?firebase[_-]?project[_-]?develop["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Firebase Key": regexp.MustCompile(`(?i)["']?firebase[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Firebase API Token": regexp.MustCompile(`(?i)["']?firebase[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Firebase API JSON": regexp.MustCompile(`(?i)["']?firebase[_-]?api[_-]?json["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - File Password": regexp.MustCompile(`(?i)["']?file[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Exp Password": regexp.MustCompile(`(?i)["']?exp[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Eureka AWS Secret Key": regexp.MustCompile(`(?i)["']?eureka[_-]?awssecretkey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Possible Leak - Env Sonatype Password": regexp.MustCompile(`(?i)["']?env[_-]?sonatype[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`),
	"Atlassian API Token": regexp.MustCompile(`(?i)(?:atlassian|confluence|jira)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([a-z0-9]{24})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"AWS Access Key": regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|ACCA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA|ASCA|APKA)[A-Z0-9]{16}`),
	"AWS Secret Key": regexp.MustCompile(`(?i)aws(.{0,20})?(?-i)['"][0-9a-zA-Z\/+]{40}['"]`),
	"Beamer API Token": regexp.MustCompile(`(?i)(?:beamer)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}(b_[a-z0-9=_\-]{44})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"BitBucket Client ID": regexp.MustCompile(`(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"BitBucket Client Secret": regexp.MustCompile(`(?i)(?:bitbucket)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([a-z0-9=_\-]{64})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"Cloudflare API Key": regexp.MustCompile(`(?i)(?:cloudflare)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([a-z0-9_-]{40})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"Cloudflare Global API Key": regexp.MustCompile(`(?i)(?:cloudflare)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([a-f0-9]{37})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"Cloudflare Origin CA Key": regexp.MustCompile(`\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"CodeCov Access Token": regexp.MustCompile(`(?i)(?:codecov)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([a-z0-9]{32})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"CoinBase Access Token": regexp.MustCompile(`(?i)(?:coinbase)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|`){0,5}([a-z0-9_-]{64})(?:['|\"|\n|\r|\s|`|;]|$)`),
	"Discord Webhook": regexp.MustCompile(`https:\/\/discordapp\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9\-]+`),
	"Google Calendar URI": regexp.MustCompile(`https:\/\/(.*)calendar\.google\.com\/calendar\/[0-9a-z\/]+\/embed\?src=[A-Za-z0-9%@&;=\-_\.\/]+`),
	"Google OAuth Access Key": regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`),
	"Mapbox Token Disclosure": regexp.MustCompile(`(pk|sk)\.eyJ1Ijoi\w+\.[\w-]*`),
	"Alibaba OSS Bucket": regexp.MustCompile(`(?:[a-zA-Z0-9-\.\_]+\.oss-[a-zA-Z0-9-\.\_]+\.aliyuncs\.com|oss-[a-zA-Z0-9-\.\_]+\.aliyuncs\.com\/[a-zA-Z0-9-\.\_]+)`),
	"Slack": regexp.MustCompile(`xox[baprs]-([0-9a-zA-Z]{10,48})?`),
	"Asymmetric Private Key": regexp.MustCompile(`-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----`),
	"Twitter Secret Key": regexp.MustCompile(`(?i)twitter(.{0,20})?[0-9a-z]{35,44}`),
	"Twitter Client ID": regexp.MustCompile(`(?i)twitter(.{0,20})?[0-9a-z]{18,25}`),
}