using Microsoft.AspNetCore.Mvc;
using WebApplication1.Services;

namespace WebApplication1.Controllers
{
    //public interface IController
    //{

    //}     

    /// <summary>
    /// TODO: using for controllers use one service
    ///     , assuming function of one service interact with one collection of mongodb
    ///     and for controller use more than one service, inject services manual
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public abstract class AbstractController<T>: ControllerBase
        //, IController
    {
        internal readonly IServices<T> _services;

        protected AbstractController(IServices<T> services)
        {
            _services = services;

        }
    }

    public abstract class AbstractController<T, T1> : ControllerBase
    {
        internal readonly IServices<T> _services;
        internal readonly IServices<T1> _services1;

        protected AbstractController(IServices<T> services, IServices<T1> services1)
        {
            _services = services;
            _services1 = services1;
        }
    }
}
