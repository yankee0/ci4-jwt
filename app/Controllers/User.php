<?php

namespace App\Controllers;

use App\Models\Users;
use Firebase\JWT\JWT;
use CodeIgniter\API\ResponseTrait;
use App\Controllers\BaseController;
use Exception;

class User extends BaseController
{
    use ResponseTrait;

    public function list()
    {
        $userModele = new Users();
        return $this->respond(['users' => $userModele->findAll()], 200);
    }

    public function login()
    {
        $userModel = new Users();

        $email = $this->request->getVar('email');
        $password = $this->request->getVar('password');

        $user = $userModel->where('email', $email)->first();

        if (is_null($user)) {
            return $this->respond(['error' => 'incorrect email.'], 401);
        }


        if (!(sha1($password) == $user['pwd'])) {
            return $this->respond(['error' => 'incorrect password.'], 401);
        }

        $key = getenv('JWT_SECRET');
        $iat = time(); // current timestamp value
        $exp = $iat + 300;

        $payload = array(
            // "iss" => "Issuer of the JWT",
            // "aud" => "Audience that the JWT",
            // "sub" => "Subject of the JWT",
            "iat" => $iat, //Time the JWT issued at
            "exp" => $exp, // Expiration time of token
            "email" => $user['email'],
        );

        $token = JWT::encode($payload, $key, 'HS256');

        $response = [
            'message' => 'Login Succesful',
            'token' => $token
        ];

        return $this->respond($response, 200);
    }

    public function register()
    {

        $rules = [
            'email' => [
                'rules' => 'required|min_length[4]|max_length[255]|valid_email|is_unique[users.email]'
            ],
            'password' => [
                'rules' => 'required|min_length[8]|max_length[255]'
            ],
            'confirm_password'  => [
                'label' => 'confirm password',
                'rules' => 'matches[password]',
            ],
        ];


        if ($this->validate($rules)) {
            $model = new Users();
            $data = [
                'email'    => $this->request->getVar('email'),
                'pwd' => sha1($this->request->getVar('password'))
            ];
            try {
                $model->save($data);
                return $this->respond(['message' => 'user registered.'], 200);
            } catch (Exception $ex) {
                return $this->respond(['errors' => 'server error'], 500);
            }

        } else {
            $response = [
                'errors' => $this->validator->getErrors(),
                'message' => 'Invalid Inputs'
            ];
            return $this->fail($response, 409);
        }

    }
}
