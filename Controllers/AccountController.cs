using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Text.Json;
using WebApplication1.Models;
using WebApplication1.Services;

namespace WebApplication1.Controllers
{
    [ApiController]
    [Route("[Controller]")]
    /// <summary>
    /// TODO: will be removed, using authorizationController instead.
    /// </summary>
    public class AccountController : AbstractController<Account>
    {
        public AccountController(IAccountServices services) : base(services)
        {
        }

        // GET: AccountController
        public ActionResult Index()
        {
            return null;
        }

        // GET: AccountController/Details/5
        public ActionResult Details(int id)
        {
            return null;
        }

        //// GET: AccountController/Create
        //public ActionResult Create()
        //{
        //    return View();
        //}

        [HttpGet]
        public string Get()
        {
            var res = _services.Get();
            string jsonString = JsonSerializer.Serialize(res);

            return jsonString;
        }

        [HttpGet("{id}")]
        public ActionResult<Account> GetbyId(string id)
        {
            return _services.GetById(id);
        }

        /// <summary>
        /// POST: AccountController/Create
        /// receive an json object
        /// </summary>
        /// <param name="account"></param>
        /// <returns></returns>
        [HttpPost("{Create}")]
        public ActionResult<Account> Create([FromBody]Account account)
        {
            try
            {
                var newAcc = _services.Create(account);
                //return RedirectToAction(nameof(Index));
                return newAcc;
            }
            catch(Exception ex)
            {
                // TODO:
                var error = ex.Message;
                return null;
            }
        }

        // TODO:
        // POST: AccountController/Edit/5
        [HttpPost("{Edit}")]
        //[ValidateAntiForgeryToken]
        public ActionResult<Account> Edit([FromBody] Account account)
        {
            try
            {
                var newAcc = _services.Update(account);
                //return RedirectToAction(nameof(Index));
                return newAcc;
            }
            catch
            {
                return null;
            }
        }

        // POST: AccountController/Delete/5
        [HttpPost("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return null;
            }
        }
    }
}
