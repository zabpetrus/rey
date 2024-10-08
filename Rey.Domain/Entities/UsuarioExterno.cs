using Microsoft.AspNetCore.Identity;

public class UsuarioExterno
{
    public long Id { get; set; }
    public string NomeDeUsuario { get; set; }
    public string HashSenha { get; set; }
    public string Email { get; set; }
    public string Cpf { get; set; }
    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
    public string RefreshTokenReset { get; internal set; }
    public string ResetPasswordTokenExpiration { get; internal set; }

    public bool VerificarSenha(string senha)
    {
        var hasher = new PasswordHasher<UsuarioExterno>();
        var result = hasher.VerifyHashedPassword(this, HashSenha, senha);
        return result == PasswordVerificationResult.Success; 
    }

    public void CriarHashSenha(string senha)
    {
        var hasher = new PasswordHasher<UsuarioExterno>();
        HashSenha = hasher.HashPassword(this, senha);
    }


}
