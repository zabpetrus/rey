using Flunt.Validations;
using Rey.Domain.Entities._Base;


namespace Rey.Domain.Entities._Abstract
{
    public abstract class Perfil : Entity
    {

        //Identificador unico do Perfil 
        public string Codigo { get; set; } = string.Empty;

        //Descricao do Perfil
        public string Descricao { get; set; } = string.Empty;

        //Verificacao se o perfil está ativo ou não
        public bool Ativo { get; set; } = true;



    }
}
