using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using Serilog;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Windows.Input;
using WebApplication1.Models.IdentityServer4;

namespace WebApplication1.Common
{
    public class ActionWithLog
    {
        /// <summary>
        /// logger can be injected 
        /// </summary>
        private ILogger _logger;
        private object _command;
        private string _functionName;

        public ActionWithLog(object command, string functionName, ILogger logger)
        {
            // logger can be injected 
            _logger = logger;

            _command = command;
            _functionName = functionName;
        }

        public TResult Run<TResult, TParam>(TParam param)
        {
            TResult r;
            var cm = _command as Func<TParam, TResult>;
            try
            {
                _logger.Information($"[{DateTime.Now}] logInject {_functionName} : running");
                r = cm(param);
            }
            catch (Exception ex)
            {
                _logger.Error($"{ex.Message}");

                throw;
            }
            finally
            {
                _logger.Information($"[{DateTime.Now}] logInject {_functionName} : end");
            }
            return r;
        }
    }

    public class ActionWithLog<TParam, TResult>
    {
        /// <summary>
        /// logger can be injected 
        /// </summary>
        private ILogger _logger;
        private Func<TParam, TResult> _command;
        private string _functionName;

        public ActionWithLog(Func<TParam, TResult> command, string functionName, ILogger logger)
        {
            _command = command;
            _functionName = functionName;

            // logger can be injected 
            _logger = logger;
        }

        public TResult Excute(TParam param)
        {
            TResult r;
            try
            {
                _logger.Information($"[{DateTime.Now}] {_functionName} : running");
                r = _command(param);
            }
            catch (Exception ex)
            {
                _logger.Error($"{ex.Message}");

                throw;
            }
            finally
            {
                _logger.Information($"[{DateTime.Now}] {_functionName} : end");
            }
            return r;
        }
    }

    public class ActionHandler<TParam, TResult>
    {
        private List<ActionWithLog<TParam, TResult>> _actions = new List<ActionWithLog<TParam, TResult>>();

        public ActionHandler()
        {

        }

        public void AddAction(ActionWithLog<TParam, TResult> newAction)
        {
            _actions.Add(newAction);
        }
    }
}
