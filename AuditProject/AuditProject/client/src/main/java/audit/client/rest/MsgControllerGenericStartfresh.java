package audit.client.rest;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import audit.client.WorkflowGenericParticipant;
import audit.client.WorkflowParticipant;
import audit.client.WorkflowParticipant3;
import audit.client.WorkflowParticipant4;
import audit.client.WorkflowParticipant5;
import audit.client.service.MsgService;
import audit.common.domain.Transaction;

import javax.servlet.http.HttpServletResponse;

import java.util.List;
import java.util.Set;

@RestController()
@RequestMapping("startfresh")
public class MsgControllerGenericStartfresh {

	private static final Logger LOG = LoggerFactory.getLogger(MsgControllerGenericStartfresh.class);

	private final WorkflowParticipant msgService;//MsgService msgService;
	// private final NodeService nodeService;

	@Autowired
	public MsgControllerGenericStartfresh(WorkflowParticipant msgService) {//public MsgController(MsgService msgService) {//this is changed to Merge if we are to combine the classes for AuditRec verif.
		this.msgService = msgService;
		// this.nodeService = nodeService;
	}

	/**
	 * Retrieve all Transactions, which aren't in a block yet
	 * 
	 * @return JSON list of Transactions
	 * @throws Exception 
	 */
	@RequestMapping(method = RequestMethod.DELETE)
	void startfresh() throws Exception {
		msgService.Startfresh();
	}

	/**
	 * Add a new Transaction to the pool. It is expected that the transaction has a
	 * valid signature and the correct hash.
	 *
	 * @param transaction
	 *            the Transaction to add
	 * @param publish
	 *            if true, this Node is going to inform all other Nodes about the
	 *            new Transaction
	 * @param response
	 *            Status Code 202 if Transaction accepted, 406 if verification fails
	 * @throws Exception 
	 */

}
