// SPDX-License-Identifier: GPL-2.0-only
/*
 * Xilinx FPGA Xilinx TSN End point driver.
 *
 * Copyright (c) 2017 Xilinx Pvt., Ltd
 *
 * Author: Saurabh Sengar <saurabhs@xilinx.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/of_net.h>
#include <linux/platform_device.h>
#include <linux/skbuff.h>

#include "xilinx_axienet_tsn.h"
#include "xilinx_tsn_switch.h"
#include "xilinx_tsn_tadma.h"
#include "xilinx_tsn_timer.h"

#define TX_BD_NUM_DEFAULT	64
#define RX_BD_NUM_DEFAULT	1024

static u8 st_pcp[8] = {4};
static uint st_count = 1;
module_param_array(st_pcp, byte, &st_count, 0644);
MODULE_PARM_DESC(st_pcp, "Array of pcp values mapped to ST class at the compile time");

static u8 res_pcp[8] = {2, 3};
static uint res_count = 2;
module_param_array(res_pcp, byte, &res_count, 0644);
MODULE_PARM_DESC(res_pcp, "Array of pcp values mapped to RES class at the compile time");

static inline int mcdma_qidx_to_txq_idx(struct axienet_local *lp, int qidx)
{
	int qno;

	for (qno = 0; qno < lp->num_tc; qno++) {
		if (!lp->txqs[qno].is_tadma &&
		    lp->txqs[qno].dmaq_idx == qidx) {
			return qno;
		}
	}

	return -EINVAL;
}

int tsn_data_path_open(struct net_device *ndev)
{
	/* The highest possible count of IRQs is twice the maximum number of
	 * queues, considering both the Tx and Rx channels
	 */
	static char irq_name[XAE_MAX_QUEUES * 2][32];
	struct axienet_local *lp = netdev_priv(ndev);
	struct net_device *emac0_ndev;
	struct net_device *emac1_ndev;
	u8 hw_addr_mask[ETH_ALEN];
	struct axienet_dma_q *q;
	u8 irq_cnt = 0;
	int ret, i = 0;

	for_each_tx_dma_queue(lp, i) {
		q = lp->dq[i];
		/*MCDMA TX RESET*/
		__axienet_device_reset_tsn(q);
		ret = mcdma_qidx_to_txq_idx(lp, i);
		if (ret < 0) {
			dev_err(&ndev->dev, "Failed to get txq for MCMDA Q%d\n",
				i);
			return -EINVAL;
		}

		q->txq_idx = ret;
	}

	for_each_rx_dma_queue(lp, i) {
		q = lp->dq[i];

		ret = axienet_mcdma_rx_q_init_tsn(ndev, q);
		/* Enable interrupts for Axi MCDMA Rx
		 */
		snprintf(irq_name[irq_cnt], sizeof(irq_name[irq_cnt]),
			 "%s_mcdma_rx_%d", ndev->name, i + 1);
		ret = request_irq(q->rx_irq, axienet_mcdma_rx_irq_tsn,
				  IRQF_SHARED, irq_name[irq_cnt], ndev);
		if (ret)
			goto err_dma_rx_irq;

		tasklet_init(&lp->dma_err_tasklet[i],
			     axienet_mcdma_err_handler_tsn,
			     (unsigned long)lp->dq[i]);
		napi_enable(&lp->napi[i]);
		irq_cnt++;
	}

	for_each_tx_dma_queue(lp, i) {
		q = lp->dq[i];

		ret = axienet_mcdma_tx_q_init_tsn(ndev, q);
		/* Enable interrupts for Axi MCDMA Tx */
		snprintf(irq_name[irq_cnt], sizeof(irq_name[irq_cnt]),
			 "%s_mcdma_tx_%d", ndev->name, i + 1);
		ret = request_irq(q->tx_irq, axienet_mcdma_tx_irq_tsn,
				  IRQF_SHARED, irq_name[irq_cnt], ndev);
		if (ret)
			goto err_dma_tx_irq;
		irq_cnt++;
	}
#if IS_ENABLED(CONFIG_AXIENET_HAS_TADMA)
	ret = axienet_tadma_open(ndev);
	if (ret)
		goto err_tadma;
#endif
	if (lp->slaves[0] && lp->slaves[1]) {
		emac0_ndev = lp->slaves[0];
		emac1_ndev = lp->slaves[1];

		for (i = 0; i < ETH_ALEN; i++)
			hw_addr_mask[i] = 0xFF;
		hw_addr_mask[5] &= 0x000000F0;
		if (!ether_addr_equal_masked(emac0_ndev->dev_addr, emac1_ndev->dev_addr,
					     hw_addr_mask))
			netdev_warn(ndev,
				    "MSB 44 bits of the MAC addresses of TSN EMAC0 and TSN EMAC1 are different");
		if (!ether_addr_equal_masked(emac0_ndev->dev_addr, ndev->dev_addr, hw_addr_mask))
			netdev_warn(ndev, "MSB 44 bits of the MAC addresses of TSN EMAC0 and TSN EP are different");
		if (!ether_addr_equal_masked(emac0_ndev->dev_addr, ndev->dev_addr, hw_addr_mask))
			netdev_warn(ndev, "MSB 44 bits of the MAC addresses of TSN EMAC1 and TSN EP are different");
	}

	netif_tx_start_all_queues(ndev);
	return 0;

#if IS_ENABLED(CONFIG_AXIENET_HAS_TADMA)
err_tadma:
	for_each_tx_dma_queue(lp, i) {
		q = lp->dq[i];
		free_irq(q->tx_irq, ndev);
	}
#endif
err_dma_tx_irq:
	for_each_rx_dma_queue(lp, i) {
		q = lp->dq[i];
		free_irq(q->rx_irq, ndev);
	}
err_dma_rx_irq:
	return ret;
}

/**
 * tsn_ep_open - TSN EP driver open routine.
 * @ndev:       Pointer to net_device structure
 *
 * Return: 0, on success.
 *          non-zero error value on failure
 *
 * This is the driver open routine. It also allocates interrupt service
 * routines, enables the interrupt lines and ISR handling. Axi Ethernet
 * core is reset through Axi DMA core. Buffer descriptors are initialized.
 */
static int tsn_ep_open(struct net_device *ndev)
{
	return tsn_data_path_open(ndev);
}

int tsn_data_path_close(struct net_device *ndev)
{
	u32 cr;
	u32 i;
	struct axienet_local *lp = netdev_priv(ndev);
	struct axienet_dma_q *q;

	for_each_tx_dma_queue(lp, i) {
		q = lp->dq[i];
		cr = axienet_dma_in32(q, XAXIDMA_TX_CR_OFFSET);
		axienet_dma_out32(q, XAXIDMA_TX_CR_OFFSET,
				  cr & (~XAXIDMA_CR_RUNSTOP_MASK));
		if (netif_running(ndev))
			netif_stop_subqueue(ndev, q->txq_idx);
		free_irq(q->tx_irq, ndev);
	}
	for_each_rx_dma_queue(lp, i) {
		q = lp->dq[i];
		cr = axienet_dma_in32(q, XAXIDMA_RX_CR_OFFSET);
		axienet_dma_out32(q, XAXIDMA_RX_CR_OFFSET,
				  cr & (~XAXIDMA_CR_RUNSTOP_MASK));
		napi_disable(&lp->napi[i]);
		tasklet_kill(&lp->dma_err_tasklet[i]);

		free_irq(q->rx_irq, ndev);
	}
#if IS_ENABLED(CONFIG_AXIENET_HAS_TADMA)
	axienet_tadma_stop(ndev);
#endif
	axienet_dma_bd_release_tsn(ndev);

	return 0;
}

/**
 * tsn_ep_stop - TSN EP driver stop routine.
 * @ndev:	Pointer to net_device structure
 *
 * Return: 0, on success.
 *
 * This is the driver stop routine. It also removes the interrupt handlers
 * and disables the interrupts. The Axi DMA Tx/Rx BDs are released.
 */
static int tsn_ep_stop(struct net_device *ndev)
{
	return tsn_data_path_close(ndev);
}

/**
 * tsn_ep_ioctl - TSN endpoint ioctl interface.
 * @dev: Pointer to the net_device structure
 * @rq: Socket ioctl interface request structure
 * @data: User data
 * @cmd: Ioctl case
 *
 * Return: 0 on success, Non-zero error value on failure.
 *
 * This is the ioctl interface for TSN end point. Currently this
 * supports only gate programming.
 */
static int tsn_ep_ioctl(struct net_device *dev, struct ifreq *rq, void __user *data, int cmd)
{
	switch (cmd) {
#if IS_ENABLED(CONFIG_XILINX_TSN_QBV)
	case SIOCCHIOCTL:
		return axienet_set_schedule(dev, data);
	case SIOC_GET_SCHED:
		return axienet_get_schedule(dev, data);
#endif
#if IS_ENABLED(CONFIG_AXIENET_HAS_TADMA)
	case SIOC_TADMA_OFF:
		return axienet_tadma_off(dev, data);
	case SIOC_TADMA_STR_ADD:
		return axienet_tadma_add_stream(dev, data);
	case SIOC_TADMA_PROG_ALL:
		return axienet_tadma_program(dev, data);
	case SIOC_TADMA_STR_FLUSH:
		return axienet_tadma_flush_stream(dev, data);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

u16 axienet_tsn_pcp_to_queue(struct net_device *ndev, struct sk_buff *skb)
{
	struct axienet_local *lp = netdev_priv(ndev);
	struct ethhdr *hdr = (struct ethhdr *)skb->data;
	u16 ether_type = ntohs(hdr->h_proto);
	u16 vlan_tci;
	u8 pcp = 0;

	if (unlikely(ether_type == ETH_P_8021Q)) {
		struct vlan_ethhdr *vhdr = (struct vlan_ethhdr *)skb->data;

		/* ether_type = ntohs(vhdr->h_vlan_encapsulated_proto); */

		vlan_tci = ntohs(vhdr->h_vlan_TCI);

		pcp = (vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
		return lp->pcpmap[pcp];
	}

	return BE_QUEUE_NUMBER;
}

static u16 axienet_tsn_ep_select_queue(struct net_device *ndev, struct sk_buff *skb,
				       struct net_device *sb_dev)
{
	return axienet_tsn_pcp_to_queue(ndev, skb);
}

/**
 * tsn_ep_xmit - TSN endpoint xmit routine.
 * @skb: Packet data
 * @ndev: Pointer to the net_device structure
 *
 * Return: Always returns NETDEV_TX_OK.
 *
 * This is dummy xmit function for endpoint as all the data path is assumed to
 * be connected by TEMAC1 as per linux view
 */
static int tsn_ep_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct axienet_tsn_txq *txq;
	struct axienet_local *lp;
	u16 map;

	map = skb_get_queue_mapping(skb);
	lp = netdev_priv(ndev);
	txq = &lp->txqs[map];
	pr_debug("map %d, is_tadma %d\n", map, txq->is_tadma);

	if (txq->is_tadma) /* ST Traffic */
		return axienet_tadma_xmit(skb, ndev, map);

	return axienet_queue_xmit_tsn(skb, ndev, map);
}

static void tsn_ep_set_mac_address(struct net_device *ndev, const void *address)
{
	if (address)
		eth_hw_addr_set(ndev, address);
	if (!address || !is_valid_ether_addr(ndev->dev_addr))
		eth_hw_addr_random(ndev);
}

/**
 * netdev_set_mac_address - Write the MAC address (from outside the driver)
 * @ndev:	Pointer to the net_device structure
 * @p:		6 byte Address to be written as MAC address
 *
 * Return: 0 for all conditions. Presently, there is no failure case.
 *
 * This function is called to initialize the MAC address of the Axi Ethernet
 * core. This is the function that goes into net_device_ops structure entry
 * ndo_set_mac_address.
 */
static int netdev_set_mac_address(struct net_device *ndev, void *p)
{
	struct sockaddr *addr = p;

	tsn_ep_set_mac_address(ndev, addr->sa_data);
	return 0;
}

#if IS_ENABLED(CONFIG_XILINX_TSN_PTP)
/**
 * tsn_ethtools_get_ts_info - Get h/w timestamping capabilities.
 * @ndev:       Pointer to net_device structure
 * @info:       Pointer to ethtool_ts_info structure
 *
 * Return: 0
 */
static int tsn_ethtools_get_ts_info(struct net_device *ndev,
				    struct kernel_ethtool_ts_info *info)
{
	info->phc_index = axienet_phc_index;
	return 0;
}
#endif

static const struct ethtool_ops ep_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_MAX_FRAMES,
	.get_sset_count	 = axienet_sset_count_tsn,
	.get_ethtool_stats = axienet_get_stats_tsn,
	.get_coalesce   = axienet_ethtools_get_coalesce,
	.set_coalesce   = axienet_ethtools_set_coalesce,
	.get_strings = axienet_strings_tsn,
#if IS_ENABLED(CONFIG_XILINX_TSN_PTP)
	.get_ts_info    = tsn_ethtools_get_ts_info,
#endif
};

static const struct net_device_ops ep_netdev_ops = {
	.ndo_open = tsn_ep_open,
	.ndo_stop = tsn_ep_stop,
	.ndo_siocdevprivate = tsn_ep_ioctl,
	.ndo_start_xmit = tsn_ep_xmit,
	.ndo_set_mac_address = netdev_set_mac_address,
	.ndo_select_queue = axienet_tsn_ep_select_queue,
#if IS_ENABLED(CONFIG_XILINX_TSN_SWITCH)
	.ndo_get_port_parent_id = tsn_switch_get_port_parent_id,
#endif
#if IS_ENABLED(CONFIG_XILINX_TSN_QBV)
	.ndo_setup_tc = axienet_tsn_shaper_tc,
#endif
};

bool xlnx_is_port_ep_netdev(const struct net_device *ndev)
{
	return ndev && (ndev->netdev_ops == &ep_netdev_ops);
}

static const struct of_device_id tsn_ep_of_match[] = {
	{ .compatible = "xlnx,tsn-ep"},
	{},
};

MODULE_DEVICE_TABLE(of, tsn_ep_of_match);

/* separate function is needed to probe tsn mcdma
 * as there is asymmetry between rx channels and tx channels
 * having unique probe for both tsn and axienet with mcdma is not possible
 */
int __maybe_unused tsn_mcdma_probe(struct platform_device *pdev, struct axienet_local *lp,
				   struct net_device *ndev)
{
	int i, ret = 0;
	struct axienet_dma_q *q;
	struct device_node *np;
	struct resource dmares;
	const char *str;
	u32 num;

	ret = of_property_count_strings(pdev->dev.of_node, "xlnx,channel-ids");
	if (ret < 0)
		return -EINVAL;

	np = of_parse_phandle(pdev->dev.of_node, "axistream-connected-rx",
			      0);
	if (!np) {
		dev_err(&pdev->dev, "could not find DMA node\n");
		return -EINVAL;
	}

	/* get number of associated queues */
	ret = of_property_read_u32(np, "xlnx,num-s2mm-channels", &num);
	if (ret < 0)
		return -EINVAL;

	lp->num_rx_queues = num;
	pr_info("%s: num_rx_queues: %d\n", __func__, lp->num_rx_queues);

	for_each_rx_dma_queue(lp, i) {
		q = devm_kzalloc(&pdev->dev, sizeof(*q), GFP_KERNEL);
		if (!q) {
			ret = -ENOMEM;
			goto err_put_node;
		}

		/* parent */
		q->lp = lp;
		lp->dq[i] = q;
		ret = of_property_read_string_index(pdev->dev.of_node,
						    "xlnx,channel-ids", i,
						    &str);
		if (ret < 0) {
			dev_err(&pdev->dev, "Failed to read channel ID for queue %d\n", i);
			goto err_put_node;
		}
		ret = kstrtou16(str, 16, &q->chan_id);
		lp->qnum[i] = i;
		lp->chan_num[i] = q->chan_id;
	}

	ret = of_address_to_resource(np, 0, &dmares);
	if (ret) {
		dev_err(&pdev->dev, "unable to get DMA resource\n");
		goto err_put_node;
	}

	lp->mcdma_regs = devm_ioremap_resource(&pdev->dev, &dmares);
	if (IS_ERR(lp->mcdma_regs)) {
		dev_err(&pdev->dev, "iormeap failed for the dma\n");
		ret = PTR_ERR(lp->mcdma_regs);
		goto err_put_node;
	}

	axienet_mcdma_rx_probe_tsn(pdev, np, ndev);
	axienet_mcdma_tx_probe_tsn(pdev, np, lp);

	of_node_put(np);
	return 0;

err_put_node:
	of_node_put(np);
	return ret;
}

static const struct axienet_config tsn_endpoint_cfg = {
	.mactype = XAXIENET_1G,
	.setoptions = NULL,
	.tx_ptplen = XAE_TX_PTP_LEN,
};

static void set_pcpmap_legacy(struct axienet_local *lp)
{
	int i;

	/* First map all PCP values to lowest priority queue */
	for (i = 0; i < XAE_MAX_TSN_TC; i++)
		lp->pcpmap[i] = 0;

	/* Map ST PCP values to Highest priority queue */
#if IS_ENABLED(CONFIG_AXIENET_HAS_TADMA)
	for (i = 0; i < st_count; i++) {
		if (st_pcp[i] >= XAE_MAX_TSN_TC) {
			pr_warn("invalid st pcp value %d ignored\n",
				st_pcp[i]);
			continue;
		}

		lp->pcpmap[st_pcp[i]] = lp->num_tc - 1;
	}
#endif

	/* Map RES PCP values to Second Highest priority queue */
	for (i = 0; i < res_count && lp->num_tc == XAE_MAX_LEGACY_TSN_TC; i++) {
		if (res_pcp[i] >= XAE_MAX_TSN_TC)
			pr_warn("invalid st pcp value %d ignored\n",
				res_pcp[i]);
		else if (lp->pcpmap[res_pcp[i]] == (lp->num_tc - 1))
			pr_warn("pcp value %d already mapped to ST\n",
				res_pcp[i]);
		else
			lp->pcpmap[res_pcp[i]] = lp->num_tc - 2;
	}
}

static void set_pcpmap_new(struct axienet_local *lp)
{
	int i;

	for (i = 0; i < lp->num_tc; i++)
		lp->pcpmap[i] = i;
}

/**
 * axienet_set_pcpmap - Gets the compile time pcp values that
 * are mapped to ST and RES traffic from st_pcp and res_pcp
 * fields and sets the pcpmap field for legacy design.
 * For eight queue design, pcpmap field is one to one mapping from
 * PCP to the queue.
 *
 * @lp:	netdev private data
 */
void axienet_set_pcpmap(struct axienet_local *lp)
{
	if (lp->num_tc <= XAE_MAX_LEGACY_TSN_TC)
		set_pcpmap_legacy(lp);
	else
		set_pcpmap_new(lp);
}

static int init_tsn_txqs_legacy(struct axienet_local *lp, u16 num_tc)
{
	struct axienet_tsn_txq *txq;
	int i;

	for (i = 0; i < lp->num_tx_queues; i++) {
		txq = &lp->txqs[i];
		txq->is_tadma = false;
		txq->dmaq_idx = i;
	}

#if IS_ENABLED(CONFIG_AXIENET_HAS_TADMA)
	txq = &lp->txqs[num_tc - 1];
	txq->is_tadma = true;
	txq->dmaq_idx = qt_st;
	lp->tadma_queues |= BIT(qt_st);
#endif
	return 0;
}

static int tsn_mcdma_chan_to_qidx(struct axienet_local *lp, u32 chan_id)
{
	int i;

	for_each_tx_dma_queue(lp, i) {
		if (lp->dq[i]->chan_id == chan_id)
			return i;
	}

	return -EINVAL;
}

static int init_tsn_txqs_new(struct axienet_local *lp, u16 num_tc)
{
	u32 total_tx_queues, queue = 0;
	struct device_node *queue_node;
	struct platform_device *pdev;
	struct axienet_tsn_txq *txq;
	struct device_node *tx_node;
	int ret = 0;

	pdev = to_platform_device(lp->dev);
	tx_node = of_parse_phandle(pdev->dev.of_node, "xlnx,tsn-tx-config", 0);
	if (!tx_node) {
		dev_err(lp->dev, "xlnx,tsn-tx-config property not defined\n");
		return -EINVAL;
	}

	ret = of_property_read_u32(tx_node, "xlnx,num-tx-queues",
				   &total_tx_queues);
	if (ret) {
		dev_err(lp->dev, "xlnx,num-tx-queues property not defined\n");
		goto exit;
	}

	if (total_tx_queues != num_tc) {
		dev_err(lp->dev,
			"total_tx_queues %d not equals to num_tc %d\n",
			total_tx_queues, num_tc);
		ret = -EINVAL;
		goto exit;
	}

	for_each_child_of_node(tx_node, queue_node) {
		u32 dma_chan;

		txq = &lp->txqs[queue];
		ret = of_property_read_u32(queue_node, "xlnx,dma-channel-num",
					   &dma_chan);
		if (ret) {
			dev_err(lp->dev,
				"Q%d xlnx,dma-channel-num not defined\n",
				queue);
			of_node_put(queue_node);
			goto exit;
		}

		if (of_property_read_bool(queue_node, "xlnx,is-tadma")) {
#if IS_ENABLED(CONFIG_AXIENET_HAS_TADMA)
			if (dma_chan != qt_st && dma_chan != qt_res) {
				dev_err(lp->dev, "Invalid TADMA stream %d\n",
					dma_chan);
				ret = -EINVAL;
				of_node_put(queue_node);
				goto exit;
			}

			lp->tadma_queues |= BIT(dma_chan);
			txq->is_tadma = true;
			txq->dmaq_idx = dma_chan;
			queue++;
#endif
		} else {
			int dmaq_idx = tsn_mcdma_chan_to_qidx(lp, dma_chan);

			if (dmaq_idx < 0) {
				dev_err(lp->dev,
					"DMA chan %d not connected to TSN IP\n",
					dma_chan);
				ret = -EINVAL;
				of_node_put(queue_node);
				goto exit;
			}

			txq->is_tadma = false;
			txq->dmaq_idx = dmaq_idx;
			queue++;
		}
	}

	if (queue != total_tx_queues) {
		dev_err(lp->dev,
			"No queues %d in DT not equal to total_tx_queues %d\n",
			queue, total_tx_queues);
		ret = -EINVAL;
		goto exit;
	}

	ret = 0;
exit:
	of_node_put(tx_node);
	return ret;
}

int axienet_init_tsn_txqs(struct axienet_local *lp, u16 num_tc)
{
	if (num_tc <= XAE_MAX_LEGACY_TSN_TC)
		return init_tsn_txqs_legacy(lp, num_tc);
	else
		return init_tsn_txqs_new(lp, num_tc);
}

/**
 * tsn_ep_probe - TSN ep pointer probe function.
 * @pdev:	Pointer to platform device structure.
 *
 * Return: 0, on success
 *	    Non-zero error value on failure.
 *
 * This is the probe routine for TSN endpoint driver.
 */
static int tsn_ep_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct axienet_local *lp;
	struct net_device *ndev;
	struct resource *ethres;
	u16 num_queues = XAE_MAX_QUEUES;
	struct device_node *np;
	u8 mac_addr[ETH_ALEN];
#if IS_ENABLED(CONFIG_XILINX_TSN_QBV)
	char irq_name[32];
#endif

	ndev = alloc_netdev_mq(sizeof(*lp), "ep",
			       NET_NAME_UNKNOWN, ether_setup, num_queues);
	if (!ndev)
		return -ENOMEM;

	platform_set_drvdata(pdev, ndev);

	SET_NETDEV_DEV(ndev, &pdev->dev);
	ndev->flags &= ~IFF_MULTICAST;  /* clear multicast */
	ndev->features = NETIF_F_SG;
	ndev->netdev_ops = &ep_netdev_ops;
	ndev->ethtool_ops = &ep_ethtool_ops;

	/* MTU range: 64 - 9000 */
	ndev->min_mtu = 64;
	ndev->max_mtu = XAE_JUMBO_MTU;

	lp = netdev_priv(ndev);
	lp->ndev = ndev;
	lp->dev = &pdev->dev;
	lp->options = XAE_OPTION_DEFAULTS;
	lp->tx_bd_num = TX_BD_NUM_DEFAULT;
	lp->rx_bd_num = RX_BD_NUM_DEFAULT;
	lp->switch_prt = PORT_EP;

	/* TODO
	 * there are two temacs or two slaves to ep
	 * get this infor from design?
	 */
	lp->slaves[0] = NULL;
	lp->slaves[1] = NULL;
	lp->ex_ep = NULL;
	lp->packet_switch = 0;

	lp->axienet_config = &tsn_endpoint_cfg;

	lp->max_frm_size = XAE_MAX_VLAN_FRAME_SIZE;

	/* check if ep has dma connected
	 * in a ep_only system dma(mcdma/tadma) is connected to temac1
	 */
	np = of_parse_phandle(pdev->dev.of_node, "axistream-connected-rx", 0);
	if (!np) {
		/* dont expose ep dev in ep_only system
		 * all functionality handled by temac1/eth1
		 */
		free_netdev(ndev);
		return 0;
	}

	/* Setup checksum offload, but default to off if not specified */
	lp->features = 0;

	lp->eth_hasnobuf = of_property_read_bool(pdev->dev.of_node,
						 "xlnx,eth-hasnobuf");

	/* Retrieve the MAC address */
	ret = of_get_mac_address(pdev->dev.of_node, mac_addr);
	if (ret)
		dev_err(&pdev->dev, "could not find MAC address\n");
	tsn_ep_set_mac_address(ndev, mac_addr);
	ret = tsn_mcdma_probe(pdev, lp, ndev);
	if (ret) {
		dev_err(&pdev->dev, "Getting MCDMA resource failed\n");
		goto err_put_node;
	}

#if IS_ENABLED(CONFIG_AXIENET_HAS_TADMA)
	ret = axienet_tadma_probe(pdev, ndev);
	if (ret) {
		dev_err(&pdev->dev, "Getting TADMA resource failed\n");
		goto err_put_node;
	}
#endif
	ret = of_property_read_u16(pdev->dev.of_node, "xlnx,num-tc",
				   &lp->num_tc);
	if (ret || !axienet_tsn_num_tc_valid(lp->num_tc)) {
		dev_err(&pdev->dev,
			"xlnx,num-tc parameter not defined or valid\n");
		goto err_put_node;
	}

	axienet_set_pcpmap(lp);
	ret = axienet_init_tsn_txqs(lp, lp->num_tc);
	if (ret) {
		dev_err(&pdev->dev, "Failed to initialize TX queues\n");
		goto err_put_node;
	}

	/* Map device registers */
	ethres = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	lp->regs = devm_ioremap_resource(&pdev->dev, ethres);
	if (IS_ERR(lp->regs)) {
		ret = PTR_ERR(lp->regs);
		goto err_put_node;
	}
#if IS_ENABLED(CONFIG_XILINX_TSN_QBV)
	lp->qbv_regs = lp->regs;

	sprintf(irq_name, "tsn_ep_scheduler_irq");
	lp->qbv_irq = platform_get_irq_byname(pdev, irq_name);
	axienet_qbv_init(ndev);
#endif

	ret = register_netdev(lp->ndev);
	if (ret) {
		dev_err(lp->dev, "register_netdev() error (%i)\n", ret);
		goto err_put_node;
	}
	of_node_put(np);
	return ret;

err_put_node:
	of_node_put(np);
	free_netdev(ndev);

	return ret;
}

static void tsn_ep_remove(struct platform_device *pdev)
{
	struct net_device *ndev = platform_get_drvdata(pdev);

	unregister_netdev(ndev);

	free_netdev(ndev);
}

struct platform_driver tsn_ep_driver = {
	.probe = tsn_ep_probe,
	.remove = tsn_ep_remove,
	.driver = {
		 .name = "tsn_ep_axienet",
		 .of_match_table = tsn_ep_of_match,
	},
};

MODULE_DESCRIPTION("Xilinx Axi Ethernet driver");
MODULE_AUTHOR("Xilinx");
MODULE_LICENSE("GPL");
