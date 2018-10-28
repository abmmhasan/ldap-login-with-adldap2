<?php

require_once("vendor/autoload.php");

class LDAP_login{
  private $provider;
  private $user;
  private $password;

  public function __construct($hosts,$DN,$luser='',$lpassword=''){
    $con = [
      'hosts'    => $hosts,
      'base_dn'  => $DN,
      'username' => $luser,
      'password' => $lpassword
    ];
    $ldap = new \Adldap\Adldap();
    $ldap->addProvider($con);
    $this->provider = $ldap->connect();
  }

  public function user($user,$password){
    if($user==""||$password=="")
      throw new \Exception ('Username and/or Password field is empty!');
    elseif(!preg_match("(^[a-z0-9\.]+$)",$user))
      throw new \Exception ('Improper Username!');
    else{
      $this->user=$user; $this->password=$password;
    }
  }

  private function json_clean_decode($json, $assoc = false, $depth = 512, $options = 0){
      $json = preg_replace("#(/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|([\s\t]//.*)|(^//.*)#", '', $json);
      return json_decode($json, $assoc, $depth, $options);
  }

  private function verifyHash($hash,$password){
   preg_match('(\{([^}]+)\})',$hash, $matches, PREG_OFFSET_CAPTURE);
    $salt = substr(base64_decode(substr($hash,6)),20);

    if(isset($matches[0][0])&&$matches[0][0]=='{MD4}')
        $val = '{MD4}'.base64_encode(hash('md4',$password.$salt,TRUE).$salt);
    elseif(isset($matches[0][0])&&$matches[0][0]=='{MD5}')
        $val='{MD5}'.base64_encode(hash('md5',$password.$salt,TRUE).$salt);
    elseif(isset($matches[0][0])&&$matches[0][0]=='{SHA}')
        $val='{SHA}'.base64_encode(hash('sha1',$password.$salt,TRUE).$salt);
    elseif(isset($matches[0][0])&&$matches[0][0]=='{SSHA}')
        $val = '{SSHA}'.base64_encode(hash('sha1',$password.$salt,TRUE).$salt);
    else
        $val=$password;
    return hash_equals($hash,$val);
  }

  public function verify(){
    $wheres = ['uid' => $this->user];
    $results = $this->provider->search()->where($wheres)->get();
    if(count($results)<1)
      throw new \Exception ('User not exist!');
    $results=$this->json_clean_decode($results, true);
    if(!isset($results[0]['userpassword'][0]))
      throw new \Exception ('Password is not set for current user!');
    if($this->verifyHash($results[0]['userpassword'][0],$this->password))
      return true;
    else
      return false;
  }
}


if(isset($_POST['user'])&&isset($_POST['pwd'])){

  $password=$_POST['pwd'];
  $user=$_POST['user'];

  $LDAP=new LDAP_login(['192.168.1.1'],'dc=XXXXXXXXX,dc=YYYYYYYYY');
  $LDAP->user($user,$password);

  if($LDAP->verify())
    echo 'Verified User';
  else
    echo "Not verified";

}else
    echo 'Post not set';
?>
