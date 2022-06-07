<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function hashMd5($hash)
    {
        $output = hash_hmac('md5', $hash, '/x!a@r-$r%an¨.&e&+f*f(f(a)');
        return $output;
    }
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        try {
            $password = $this->hashMd5(request('password'));
    
        if (User::where('email', request('email'))->orWhere('login', request('email'))->where('password', $password)->count() > 0) {

            //OBTER DADOS DO USUÁRIO
            $user = User::where('email', request('email'))->orWhere('login', request('email'))->where('password', $password)->first();
            
            if (!$token = auth()->login($user)) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }
        }


        return $this->respondWithToken($token);
        } catch (Exception $th) {
            return response()->json(['error' => $th->getMessage()], 500);
        }
       
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        try {
            auth()->logout(true);

            return response()->json(['message' => 'Usuario deslogado com sucesso.']);
        } catch (\Throwable $th) {
            return response()->json(['err' => 'Ocorreu um erro'], 500);
        }
      
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
