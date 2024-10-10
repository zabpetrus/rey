using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Rey.Domain.Entities._Base;
using Rey.Domain.Enums;
using System.Collections;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;
namespace Rey.Domain.Entities._Abstract
{
    public abstract class Usuario : Entity
    {
        public string Nome { get; set; }
        public string Cpf { get; set; }
        public string Email { get; set; }
        public string Telefone { get; set; }
        public string Sal { get; private set; }
        public string Senha { get; private set; }
        public string SenhaHash { get; private set; }
        public bool? Ativo { get; set; }


        public Usuario()
        {

        }

        // Método para definir e configurar a senha
        public void ConfigurarSenha(string senha)
        {
            if (string.IsNullOrWhiteSpace(senha))
            {
                throw new ArgumentException("A senha não pode ser nula ou vazia.", nameof(senha));
            }

            Senha = senha;
            Sal = GerarSal();
            SenhaHash = HashSenha(Senha, Sal);
        }

        private string HashSenha(string senha, string sal)
        {
            using (var sha256 = SHA256.Create())
            {
                var bytes = Encoding.UTF8.GetBytes(senha + sal);
                var hash = sha256.ComputeHash(bytes);
                return Convert.ToBase64String(hash);
            }
        }

        public string GerarSal()
        {
            byte[] bytes = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(bytes);
            }
            return Convert.ToBase64String(bytes);
        }

        public bool VerificarSenha(string senha)
        {
            if (string.IsNullOrWhiteSpace(senha))
            {
                throw new ArgumentException("A senha não pode ser nula ou vazia.", nameof(senha));
            }

            string hash = HashSenha(senha, Sal);
            return SenhaHash == hash;
        }

        public void RedefinirSenha(string novaSenha)
        {
            if (string.IsNullOrWhiteSpace(novaSenha))
            {
                throw new ArgumentException("A nova senha não pode ser nula ou vazia.", nameof(novaSenha));
            }

            Senha = novaSenha;
            Sal = GerarSal();
            SenhaHash = HashSenha(Senha, Sal);
        }
    }

}
