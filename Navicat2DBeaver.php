<?php
#Navicat的connections.ncx转化为DBeaver所需data-sources.json
#DBeaver所需data-sources.json 数据库配置路径参考：https://qa.1r1g.com/sf/ask/3959300761/
#Navicat 密码解密参考：#https://imxgr.com/backend/125.html
#Author：了然如一
#20221017
$xml             = simplexml_load_string(file_get_contents('connections.ncx')); //xml转object
$xml             = json_encode($xml); //objecct转json
$xml             = json_decode($xml, true); //json转array
$output          = [];
$credentials     = [];
$navicatPassword = new NavicatPassword(12);
foreach ($xml['Connection'] as $connection) {
    $detail   = $connection['@attributes'];
    $name     = $detail['ConnectionName'];
    $host     = $detail['Host'];
    $port     = $detail['Port'];
    $user     = $detail['UserName'];
    $password = $navicatPassword->decrypt($detail['Password']);
    $sshKey   = $detail['SSH_PrivateKey']??'';
    $sshPort  = $detail['SSH_Port']??'';
    $sshHost  = $detail['SSH_Host']??'';
    $id       = md5($name);
    $id       = 'mysql8-'.substr($id, 0, 11).'-'.substr($id, 12, 16);
    if (empty($sshKey)) {
        $output[$id]         = [
            'provider'       => 'mysql',
            'driver'         => 'mysql8',
            'name'           => $name,
            'save-password'  => true,
            'read-only'      => false,
            'configuration'  => [
                'host'       => $host,
                'port'       => $port,
                'url'        => "jdbc:mysql://{$host}:{$port}/",
                'home'       => 'mysql_client',
                'type'       => 'dev',
                'auth-model' => 'native',
                'handlers'   => (object)[]
            ]
        ];
    } else {
        $output[$id]         = [
            'provider'       => 'mysql',
            'driver'         => 'mysql8',
            'name'           => $name,
            'save-password'  => true,
            'read-only'      => false,
            'configuration'  => [
                'host'       => $host,
                'port'       => $port,
                'url'        => "jdbc:mysql://{$host}:{$port}/",
                'home'       => 'mysql_client',
                'type'       => 'dev',
                'auth-model' => 'native',
                'handlers'   => [
                    'ssh_tunnel'                     => [
                        'type'                       =>  'TUNNEL',
                        'enabled'                    =>  true,
                        'save-password'              =>  true,
                        'properties'                 =>  [
                            'host'                   =>  $sshPort,
                            'port'                   =>  $sshHost,
                            'authType'               =>  'PUBLIC_KEY',
                            'keyPath'                =>  $sshKey,
                            'implementation'         =>  'sshj',
                            'bypassHostVerification' =>  false,
                            'localHost'              =>  '',
                            'remoteHost'             =>  ''
                        ]
                    ]
                ]
            ]
        ];
    }
    if (!empty($user)) {
        $credentials[$id]  =  [
            '#connection'  => [
                'user'     => $user,
                'password' => $password,
            ]
        ];
    }
}
$output = [
    'folders'          => (object)[],
    'connections'      => $output,
    'connection-types' => [
        'dev'          => [
            'name'                    => '开发',
            'color'                   => '255,255,255',
            'description'             => '常规开发数据库',
            'auto-commit'             => true,
            'confirm-execute'         => false,
            'confirm-data-change'     => false,
            'auto-close-transactions' => false,
        ],
    ],
];
$begin   = 'aNj9VgFMUBvf3nfEBgaGQg==';
$tmpFile = 'credentials.json';
file_put_contents('data-sources.json', json_encode($output, JSON_UNESCAPED_UNICODE|JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));
file_put_contents($tmpFile, base64_decode($begin).json_encode($credentials));
shell_exec('openssl aes-128-cbc -e -nosalt -K babb4a9f774ab853c96c2d653dfe544a -iv 00000000000000000000000000000000 -in credentials.json -out credentials-config.json');
unlink($tmpFile);

class NavicatPassword
{
    protected $version = 0;
    protected $aesKey = 'libcckeylibcckey';
    protected $aesIv = 'libcciv libcciv ';
    protected $blowString = '3DC5CA39';
    protected $blowKey = null;
    protected $blowIv = null;
     
    public function __construct($version = 12)
    {
        $this->version = $version;
        $this->blowKey = sha1('3DC5CA39', true);
        $this->blowIv = hex2bin('d9c7c3c8870d64bd');
    }
     
    public function encrypt($string)
    {
        $result = FALSE;
        switch ($this->version) {
            case 11:
                $result = $this->encryptEleven($string);
                break;
            case 12:
                $result = $this->encryptTwelve($string);
                break;
            default:
                break;
        }
         
        return $result;
    }
     
    protected function encryptEleven($string)
    {
        $round = intval(floor(strlen($string) / 8));
        $leftLength = strlen($string) % 8;
        $result = '';
        $currentVector = $this->blowIv;
         
        for ($i = 0; $i < $round; $i++) {
            $temp = $this->encryptBlock($this->xorBytes(substr($string, 8 * $i, 8), $currentVector));
            $currentVector = $this->xorBytes($currentVector, $temp);
            $result .= $temp;
        }
         
        if ($leftLength) {
            $currentVector = $this->encryptBlock($currentVector);
            $result .= $this->xorBytes(substr($string, 8 * $i, $leftLength), $currentVector);
        }
         
        return strtoupper(bin2hex($result));
    }
     
    protected function encryptBlock($block)
    {
        return openssl_encrypt($block, 'BF-ECB', $this->blowKey, OPENSSL_RAW_DATA|OPENSSL_NO_PADDING);
    }
     
    protected function decryptBlock($block)
    {
        return openssl_decrypt($block, 'BF-ECB', $this->blowKey, OPENSSL_RAW_DATA|OPENSSL_NO_PADDING);
    }
     
    protected function xorBytes($str1, $str2)
    {
        $result = '';
        for ($i = 0; $i < strlen($str1); $i++) {
            $result .= chr(ord($str1[$i]) ^ ord($str2[$i]));
        }
         
        return $result;
    }
     
    protected function encryptTwelve($string)
    {
        $result = openssl_encrypt($string, 'AES-128-CBC', $this->aesKey, OPENSSL_RAW_DATA, $this->aesIv);
        return strtoupper(bin2hex($result));
    }
     
    public function decrypt($string)
    {
        $result = FALSE;
        switch ($this->version) {
            case 11:
                $result = $this->decryptEleven($string);
                break;
            case 12:
                $result = $this->decryptTwelve($string);
                break;
            default:
                break;
        }
         
        return $result;
    }
     
    protected function decryptEleven($upperString)
    {
        $string = hex2bin(strtolower($upperString));
         
        $round = intval(floor(strlen($string) / 8));
        $leftLength = strlen($string) % 8;
        $result = '';
        $currentVector = $this->blowIv;
         
        for ($i = 0; $i < $round; $i++) {
            $encryptedBlock = substr($string, 8 * $i, 8);
            $temp = $this->xorBytes($this->decryptBlock($encryptedBlock), $currentVector);
            $currentVector = $this->xorBytes($currentVector, $encryptedBlock);
            $result .= $temp;
        }
         
        if ($leftLength) {
            $currentVector = $this->encryptBlock($currentVector);
            $result .= $this->xorBytes(substr($string, 8 * $i, $leftLength), $currentVector);
        }
         
        return $result;
    }
     
    protected function decryptTwelve($upperString)
    {
        $string = hex2bin(strtolower($upperString));
        return openssl_decrypt($string, 'AES-128-CBC', $this->aesKey, OPENSSL_RAW_DATA, $this->aesIv);
    }
};