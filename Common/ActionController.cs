using Microsoft.AspNetCore.Mvc;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace WebApplication1.Common
{
    public class ActionController
    {
        /// <summary>
        /// logger can be injected 
        /// </summary>
        private ILogger _logger;
        //private ActionManager _actions;

        public ActionController(ILogger logger)
        {
            // logger can be injected 
            _logger = logger;
        }

        //public void AddActions<TResult, TParam>(List<Func<TParam, TResult>> action)
        //{

        //}

        public Task ExecuteResultAsync(ActionContext context)
        {
            throw new NotImplementedException();
        }

        public TResult Run<TResult, TParam>(Func<TParam, TResult> func, TParam param)
        {
            TResult r;
            try
            {
                _logger.Information($"[{DateTime.Now}] logInject {func.Method.Name} : running");
                r = func(param);
            }
            catch (Exception ex)
            {
                _logger.Error($"{ex.Message}");

                throw;
            }
            finally
            {
                _logger.Information($"[{DateTime.Now}] logInject {func.Method.Name} : end");
            }
            return r;
        }
    }

    //public class ActionManager
    //{
    //    public 
    //}
}
