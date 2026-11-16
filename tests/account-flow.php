<?php
require __DIR__ . '/../openid-connect/includes/Protocol.php';
require __DIR__ . '/../openid-connect/includes/AccountFlow.php';
use OpenIDConnect\AccountFlow;
$count=0;
function check($ok,$name){global $count;if(!$ok){throw new RuntimeException('FAIL: '.$name);}$count++;}
function rejects($fn,$name){try{$fn();}catch(RuntimeException){check(true,$name);return;}throw new RuntimeException('FAIL: '.$name);}
class WP_User { public function __construct(public int $ID,public string $user_login,public string $user_email,public string $user_pass='hash',public array $roles=['subscriber']){} }
class WP_Error { public array $errors=[];function __construct($code='',$text=''){if($code)$this->add($code,$text);}function add($code,$text){$this->errors[$code]=$text;} }
$users=[1=>new WP_User(1,'recovery','admin@example.test','admin-hash',['administrator']),2=>new WP_User(2,'managed','member@example.test')];
$meta=[2=>['_openid_connect_created'=>'1','_openid_connect_identity'=>'stable-subject']];
$options=['enabled'=>true,'enforce_sso'=>true,'public_flow'=>true,'issuer'=>'https://id.test/realms/community','client_id'=>'site','account_url'=>'https://site.test/account/','provider_account_url'=>'','allow_http'=>false];
function get_user_meta($id,$key,$single){return $GLOBALS['meta'][$id][$key]??'';}
function get_user_by($field,$value){foreach($GLOBALS['users'] as $u){if(($field==='login'&&$u->user_login===$value)||($field==='email'&&$u->user_email===$value)||($field==='id'&&$u->ID===$value))return $u;}return false;}
function get_userdata($id){return $GLOBALS['users'][$id]??false;}
function get_users($args){return array_keys($GLOBALS['meta']);}
function is_email($email){return filter_var($email,FILTER_VALIDATE_EMAIL);}
function email_exists($email){$u=get_user_by('email',$email);return $u?$u->ID:false;}
function wp_update_user($args){$GLOBALS['users'][$args['ID']]->user_email=$args['user_email'];return $args['ID'];}
function is_wp_error($result){return $result instanceof WP_Error;}
function home_url($path='/'){return 'https://site.test'.$path;}
function site_url($path,$scheme=''){return 'https://site.test/'.$path;}
function admin_url($path=''){return 'https://site.test/wp-admin/'.$path;}
function wp_get_environment_type(){return 'production';}
function user_can($u,$cap){return in_array('editor',$u->roles)||in_array('administrator',$u->roles);}
function wp_get_session_token(){return 'token';}
class WP_Session_Tokens { public static array $records=[];public static array $destroyed=[];function __construct(private int $id){} static function get_instance($id){return new self($id);}function get($token){return self::$records[$this->id]??[];}function destroy_all(){self::$destroyed[]=$this->id;} }
class WP_Application_Passwords {static array $deleted=[];static function delete_all_application_passwords($id){self::$deleted[]=$id;}}
class DB { public string $users='users';public array $updates=[];function update($table,$data,$where){$this->updates[]=[$data,$where];} }
$wpdb=new DB();function clean_user_cache($id){}
$flow=new AccountFlow(fn()=>$GLOBALS['options']);
check($flow->authenticate($users[2],'managed','correct') instanceof WP_Error,'managed username login blocked');
check($flow->authenticate(null,'member@example.test','correct') instanceof WP_Error,'managed email login blocked');
check($flow->authenticate($users[1],'recovery','correct')===$users[1],'recovery authentication preserved');
check(!$flow->checkPassword(true,'correct','hash',2),'managed password verification denied');
check($flow->checkPassword(true,'correct','hash',1),'recovery password verification preserved');
check(!$flow->allowReset(true,2)&&$flow->allowReset(true,1),'reset policy scoped to managed account');
$errors=new WP_Error();$flow->validateReset($errors,$users[2]);check(isset($errors->errors['openid_connect_sso_required']),'previously issued reset links rejected');
check(!$flow->applicationPasswords(true,$users[2])&&$flow->applicationPasswords(true,$users[1]),'application password boundary');
check(!$flow->passwordFields(true,$users[2]),'managed password controls hidden');
$data=$flow->protectIdentity(['user_email'=>'attacker@test.invalid','user_pass'=>'new'],true,2,[]);
check($data['user_email']==='member@example.test'&&$data['user_pass']==='hash'&&$data['user_activation_key']==='','local identity changes blocked');
check($flow->protectIdentity(['user_email'=>'other@test.invalid'],true,1,[])['user_email']==='other@test.invalid','recovery profile preserved');
rejects(fn()=>$flow->syncEmail($users[2],['email'=>'new@example.test','email_verified'=>false]),'unverified email update rejected');
rejects(fn()=>$flow->syncEmail($users[2],['email'=>'admin@example.test','email_verified'=>true]),'email collision rejected');
$flow->syncEmail($users[2],['email'=>'new@example.test','email_verified'=>true]);check($users[2]->user_email==='new@example.test','verified email synchronized');
check($flow->sessionUser(2)===false&&$flow->sessionUser(1)===1,'unmarked managed session denied but recovery preserved');
WP_Session_Tokens::$records[2]=['openid_connect'=>['issuer'=>$options['issuer'],'client_id'=>'site']];
check($flow->sessionUser(2)===2,'valid OIDC session accepted');
WP_Session_Tokens::$records[2]['openid_connect']['client_id']='different';check($flow->sessionUser(2)===false,'mismatched provider session rejected');
$flow->policyChanged([],['enforce_sso'=>true]);check(WP_Session_Tokens::$destroyed===[2]&&WP_Application_Passwords::$deleted===[2],'policy transition revokes only managed credentials');
check($wpdb->updates[0][1]===['ID'=>2],'reset token invalidation scoped');
$base='https://site.test/';$fallback=$options['account_url'];
foreach(['https://evil.test','//evil.test','https://site.test.evil.test','https://site.test:444/a','http://site.test/a','https://u:p@site.test/a','/wp-login.php?action=logout','/a%0d%0aLocation:x','/\\evil.test'] as $bad){check(AccountFlow::localReturn($bad,$base,$fallback)===$fallback,'unsafe return '.$bad);}
check(AccountFlow::localReturn('/articles/?page=2',$base,$fallback)==='https://site.test/articles/?page=2','same-site return preserved');
check($flow->destination($users[2],'')===$fallback,'subscriber defaults to frontend account');
check($flow->destination($users[1],'')===admin_url(),'editorial user defaults to dashboard');
check($flow->destination($users[2],admin_url())===$fallback,'subscriber admin target replaced');
check($flow->destination($users[2],'https://site.test/articles/')==='https://site.test/articles/','intended page restored');
check($flow->managementUrl()==='https://id.test/realms/community/account/','generic account console URL');
$options['provider_account_url']='https://evil.test';rejects(fn()=>$flow->managementUrl(),'foreign management URL rejected');
$options['enforce_sso']=false;check($flow->checkPassword(true,'correct','hash',2),'generic enforcement option defaults independently');
echo "Account-flow checks passed: $count\n";
