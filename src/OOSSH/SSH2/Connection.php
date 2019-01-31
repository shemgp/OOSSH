<?php

namespace OOSSH\SSH2;

use OOSSH\Authentication\AuthenticationInterface,
    OOSSH\Exception as Exception;

class Connection
{
    const
        FINGERPRINT_MD5  = SSH2_FINGERPRINT_MD5,
        FINGERPRINT_SHA1 = SSH2_FINGERPRINT_SHA1,
        FINGERPRINT_HEX  = SSH2_FINGERPRINT_HEX,
        FINGERPRINT_RAW  = SSH2_FINGERPRINT_RAW;

    /**
     * @var resource
     */
    protected $resource;

    /**
     * @var string
     */
    protected $hostname;

    /**
     * @var int
     */
    protected $port;

    /**
     * @var bool false
     */
    protected $isAuthenticated;

    protected $isConnected;

    protected $isInBlock;

    protected $commands;

    protected $output;

    protected $globalOutput;

    protected $isShell;

    protected $shellStream;

    protected $microseconds_timeout;

    /**
     * @param string $hostname
     * @param int $port
     */
    public function __construct($hostname, $port = 22, $microseconds_timeout = 10000000)
    {
        $this->hostname        = $hostname;
        $this->port            = $port;
        $this->isAuthenticated = false;
        $this->isConnected     = false;
        $this->isInBlock       = false;
        $this->commands        = array();
        $this->isShell         = false;
        $this->globalOutput    = '';
        $this->microseconds_timeout = $microseconds_timeout;
    }

    /**
     * Initiate connection to the server.
     *
     * @throws \OOSH\Exception\ConnectionRefused
     *
     * @return Connection
     */
    public function connect()
    {
        $this->resource = \ssh2_connect($this->hostname, $this->port);

        if (false === $this->resource) {
            throw new Exception\ConnectionRefused();
        }

        $this->isConnected = true;

        return $this;
    }

    /**
     * Verify if fingerprint is correct.
     *
     * @param $fingerprint
     * @param [$flags]
     * @throws Exception\BadFingerprint
     * @return Connection
     */
    public function check($fingerprint, $flags = null)
    {
        $flags = null === $flags ? self::FINGERPRINT_MD5 | self::FINGERPRINT_HEX : $flags;

        if (strtoupper(\ssh2_fingerprint($this->resource, $flags)) !== strtoupper($fingerprint)) {
            throw new Exception\BadFingerprint;
        }

        return $this;
    }

    /**
     * Login to the server.
     *
     * @param $authentication OOSSH\Authentication\Interface implementation
     * @return Connection
     */
    public function authenticate(AuthenticationInterface $authentication)
    {
        $authentication->authenticate($this->resource);
        $this->isAuthenticated = true;

        return $this;
    }

    /**
     * Set execution of commands using a shell.
     *
     * @param $waitForOptions
     * @return Connection
     */
    public function setShell($waitForOptions)
    {
        $this->isShell = true;

        $this->shellStream = ssh2_shell($this->resource);

        // collect login screen so it won't be included in next exec
        $this->output = '';
        $stdio  = \ssh2_fetch_stream($this->shellStream, SSH2_STREAM_STDIO);
        $stderr = \ssh2_fetch_stream($this->shellStream, SSH2_STREAM_STDERR);
        $this->waitFor($stdio, $waitForOptions);

        return $this;
    }

    /**
     * Send a command and gather output (but don't return output yet).
     *
     * @param $command
     * @param [$callback] callback to consume commands
     * @param [$waitForOptions]
     * @return Connection
     */
    public function exec($command, $callback = null, $waitForOptions = [])
    {
        if ($this->isInBlock)
        {
            return $this->addCommand($command);
        }

        if ($this->isShell)
        {
            fwrite($this->shellStream, $command."\n");
            $stream = $this->shellStream;
        }
        else
        {
            $stream = \ssh2_exec($this->resource, $command);
        }

        // call callback, or null callback to collect output
        if ($callback === null)
            $this->callCallback($stream, function ($stdio, $stderr) {}, $waitForOptions);
        else
            $this->callCallback($stream, $callback, $waitForOptions);

        $this->addCommand($command);

        return $this;
    }

    /**
     * Start block execution by gathering exec commands.
     *
     * @return Connection
     */
    public function begin()
    {
        $this->isInBlock = true;

        return $this;
    }

    /**
     * End block execution by sending commands to server and collecting output.
     *
     * @param [$callback]
     * @param [$waitForOptions]
     * @return Connection
     */
    public function end($callback = null, $waitForOptions = null)
    {
        $stream = ssh2_shell($this->resource);

        foreach ($this->commands as $command) {
            fwrite($stream, $command."\n");
        }

        if (null !== $callback)
        {
            $this->callCallback($stream, $callback, $waitForOptions);
        }
        else
        {
            $this->callCallback($stream, function ($stdio, $stderr) {}, $waitForOptions);
        }

        $this->isInBlock = false;
        $this->commands  = array();

        return $this;
    }

    /**
     * Helper function to add commands.
     * Used in block execution and to remove commands in output.
     *
     * @param $command
     * @return Connection
     */
    protected function addCommand($command)
    {
        $this->commands[] = $command;

        return $this;
    }

    /**
     * Helper function to wait for output by characters or time
     *
     * @param $stdio Output stream
     * @param [$waitForOptions] 'start', 'end', 'char', or 'wait_before_end'
     *            start - wait for regex before sending commands
     *            end - wait for regex before stopping the collection of output
     *            char - true if wait for at least a character collecting/ending
     *            wait_before_end - time to wait before ending collection
     * @return Connection
     */
    protected function waitFor($stdio, $waitForOptions = [])
    {
        // use default options or the ones set
        $default_options = [
                    'start' => null,
                    'end' => null,
                    'char' => false,
                    'wait_before_end' => 10000
                ];
        foreach($default_options as $key => $value)
        {
            if (isset($waitForOptions[$key]))
                $$key = $waitForOptions[$key];
            else
                $$key = $value;
        }

        // collect output
        $this->output = '';
        $start_cnt = 0;
        $end_cnt = 0;
        $ending_time = time() + ($this->microseconds_timeout / 1000000);
        do
        {
            if (time() >= $ending_time)
                throw new \Exception('Timeout reached');

            // collect output
            $current_output      = stream_get_contents($stdio);
            $this->output       .= $current_output;
            $this->globalOutput .= $current_output;

            // Starting phase
            // wait for $start regex before continuing
            try
            {
                $start = substr($start, 1, strlen($start) - 2);
                $start = preg_replace('/^\//', '\/', $start);
                $start = preg_replace('/([^\\\])\//', '$1\/', $start);
                $start = '/'.$start.'/';
                $match = preg_match($start, $this->output);
            }
            catch (\Exception $e)
            {
                throw new \Exception('Regex error with string: '.$start);
            }
            if ($start !== null && !$match)
            {
                usleep(1000);
                continue;
            }

            // wait for seven blanks before continuing
            if ($current_output == '' && $start_cnt < 7)
            {
                // if char is set, wait at least a character before continuing
                if ($char === false)
                    $start_cnt++;
            }

            // found a character, continue
            if ($current_output != '')
            {
                $start_cnt = 7;
            }

            // Ending phase
            // when no more outputs, start ending
            if ($current_output == '' && $start_cnt >= 7)
            {
                usleep($wait_before_end);
                $end_cnt++;
            }
            // when match regex or 7 no outputs, stop collecting
            if (($end === null && $end_cnt >= 7) ||
                    ($end !== null && preg_match($end, $this->output)))
                break;
            usleep(1000);
        }
        while (true);

        return $this;
    }

    /**
     * Call callback to get results/output
     *
     * @param $stream ssh2 stream
     * @param $callback in format function ($out, $err) {}
     * @param [$waitForOptions]
     * @return Connection
     */
    protected function callCallback($stream, $callback, $waitForOptions = [])
    {
        if (!is_callable($callback))
        {
            throw new \InvalidArgumentException('$callback must be a callable');
        }

        $stdio  = \ssh2_fetch_stream($stream, SSH2_STREAM_STDIO);
        $stderr = \ssh2_fetch_stream($stream, SSH2_STREAM_STDERR);

        if ($this->isInBlock || $this->isShell)
        {
            $this->waitFor($stdio, $waitForOptions);
        }
        else
        {
            stream_set_blocking($stdio, true);
            stream_set_blocking($stderr, true);
            $this->output = '';
            $this->output = stream_get_contents($stdio);
        }

        call_user_func($callback, $this->output, stream_get_contents($stderr));

        return $this;
    }

    /**
     * @param boolean $isAuthenticated
     */
    public function setIsAuthenticated($isAuthenticated)
    {
        $this->isAuthenticated = $isAuthenticated;
    }

    /**
     * @return boolean
     */
    public function isAuthenticated()
    {
        return $this->isAuthenticated;
    }

    /**
     * @return boolean
     */
    public function isConnected()
    {
        return $this->isConnected;
    }

    /**
     * return output of exec command
     *
     * @param $options['just_output'] set if output will include commmands
     *                                & prompts or not
     * @return string
     */
    public function getOutput($options = [])
    {
        $default_options = ['just_output' => true];
        foreach($default_options as $key => $value)
        {
            if (isset($options[$key]))
                $$key = $options[$key];
            else
                $$key = $value;
        }

        if ($just_output)
        {
            $output_array = explode("\n", $this->output);
            foreach($output_array as $key => $line)
            {
                foreach($this->commands as $command)
                {
                    if (strpos($line, $command) === 0)
                    {
                        // remove command from output
                        unset($output_array[$key]);
                    }
                }
            }
            // remove last line
            unset($output_array[count($output_array)]);
            return join("\n", $output_array);
        }

        return $this->output;
    }

    /**
     * Get all output since login
     *
     * @return string
     */
    public function getGlobalOutput()
    {
        return $this->globalOutput;
    }


    /**
     * Disconect the resource
     *
     */
    public function disconnect()
    {
        ssh2_exec($this->resource, 'exit');
        unset($this->resource);
    }

    /**
     * Set timeout in microseconds
     *
     * @param $microsecons_timeout Timeout in microseconds
     */
    public function setMicrosecondsTimeout($microseconds_timeout)
    {
        $this->microseconds_timeout = $microseconds_timeout;
    }
}
